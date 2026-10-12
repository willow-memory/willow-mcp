"""The installer's half of D1 (docs/design/d1-trust-dir-identity.md, bite 2):
write, check and re-record ``/etc/willow-mcp/trust-identity``.

``deploy/manifest-grant/install.sh`` runs this as root, from the pinned
trust-owner venv (``$PY -I -m willow_mcp.install_steps.trust_identity_record
<command> ...``), so the bytes of the record are exactly
:func:`willow_mcp.trust_identity.render_record`'s and nothing is re-implemented
in shell. No runtime reader uses the record yet (bite 3+): this module only
makes it exist, keeps it honest and lets an operator accept a change.

Commands (one line per fact on stdout; refusals on stderr as ``STOP: ...``):

``precheck``   before step 1 / ``--rotate``: ``ABSENT`` or ``MATCH`` (exit 0),
               ``DIFFERS`` + diff lines (exit 10), ``INVALID: reason`` (11).
``check``      the ``--check`` lines: ``[ok]`` / ``[FAIL]`` / ``[info]``
               (exit 0, 1, 4 for absent).
``audit``      the read-only audit run before a first or a re-recorded
               record (owners, modes, kinds, the D4.5/F1 shapes); exit 0 only
               when every line is ``[ok]``; the last stdout line is
               ``snapshot=<hex>``, a digest of the ``(fsid, ino)`` identity
               found, which ``write --expect-snapshot`` re-checks.
``diff``       old record against the live tree (the re-record preview).
``write``      ``--mode first|rewrite|rerecord``; atomic (temp in the same
               root-owned directory, validated, ``os.replace``).

Nothing here reads vault material: the audit ``lstat``s ``$WILLOW_HOME`` and
the trust directories, reads seat manifests (public, trust-owner-owned) for
``app_id`` only, and never opens ``$WILLOW_HOME/env`` or any key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Optional

from .. import trust_identity as ti
from .. import trust_marker as tm

#: gid of the record file. Test seam only, beside ``trust_marker._ROOT_UID``.
_ROOT_GID = 0

#: Governed files directly inside ``constitutional/`` (shape-checked; the
#: other entries there are reported, not failed -- review_queue.json etc. are
#: deliberately left broker-owned by install.sh step 1).
_GOVERNED_CONST = frozenset({
    "trust.env", "pre-approved.json", "syscall-table.json", "frank_head_anchor.json",
})

_MAX_WALK = 50000
_MAX_MANIFEST = 1 << 20
_FPR_LINE = re.compile(r"^(?:export )?WILLOW_PGP_FINGERPRINT=([0-9A-Fa-f]{40})$")
_BULLET = "           - "


class Refused(Exception):
    """A refusal; main() prints ``STOP: <message>`` and exits 2."""


# ── helpers ────────────────────────────────────────────────────────────────

def snapshot_of(rec: ti.IdentityRecord) -> str:
    """Digest of the ``(fsid, ino)`` of ``$WILLOW_HOME`` and the recorded
    directories (not uid/mode/igen, which a legitimate step 1 may touch)."""
    parts = [f"home={rec.home.fsid:x}:{rec.home.ino}"]
    parts += [f"{n}={rec.dir_identity(n).fsid:x}:{rec.dir_identity(n).ino}" for n in ti.RECORDED_DIRS]
    return hashlib.sha256(";".join(parts).encode()).hexdigest()[:16]


def confirm_token(rec: ti.IdentityRecord) -> str:
    """The string a re-record must be confirmed with: a digest of the exact
    record text about to be written, so it commits to the diff shown."""
    return "rr-" + hashlib.sha256(ti.render_record(rec).encode()).hexdigest()[:12]


def _live(home: str, fingerprint: str) -> ti.IdentityRecord:
    return ti.compute_record(home, trust_fingerprint=fingerprint)


def _old_record() -> "tuple[Optional[ti.IdentityRecord], Optional[str]]":
    """(record, None) valid; (None, None) absent; (None, reason) invalid."""
    try:
        return ti.read_record(), None
    except ti.TrustIdentityError as exc:
        return None, str(exc)


def _short(reason: str) -> str:
    # _bad() appends fixed advice after the reason; keep only the reason.
    m = re.match(r"trust-identity record \S+ is not trustworthy: (.*?)\. This box pins", reason, re.S)
    return (m.group(1) if m else reason)[:300]


def _table(rec: ti.IdentityRecord) -> list[str]:
    out = [f"  willow_home          {rec.willow_home}", f"  home                 {rec.home.render()}"]
    out += [f"  {('dir.' + n):<20} {rec.dir_identity(n).render()}" for n in ti.RECORDED_DIRS]
    out.append(f"  trust_fingerprint    {rec.trust_fingerprint}")
    return out


# ── the atomic writer ──────────────────────────────────────────────────────

def _read_bytes(p: Path) -> Optional[bytes]:
    try:
        return p.read_bytes()
    except OSError:
        return None


def install_record(rec: ti.IdentityRecord) -> None:
    """Write ``rec`` to the record path: temp file beside it, ``0644``,
    root-owned, validated by re-parsing, then ``os.replace``; the landed file
    is read back with :func:`ti.read_record`. On any failure the previous
    bytes (or absence) are restored, so nothing half-written or invalid is
    left behind. Raises :class:`Refused`."""
    target = ti.record_path()
    text = ti.render_record(rec)
    parent = target.parent
    # The reader refuses a record whose D4 marker is invalid or names another
    # home: refuse to write one that would be born invalid.
    try:
        marker = tm.read_marker()
    except tm.TrustMarkerError as exc:
        raise Refused(f"the D4 marker is not valid, so no record can be written: {str(exc)[:200]}") from exc
    if marker is None:
        raise Refused("there is no D4 trust-provisioned marker: the record is written only after the marker")
    if marker.willow_home != rec.willow_home:
        raise Refused(f"the marker binds {marker.willow_home}, not {rec.willow_home}")
    try:
        ti._check_root_dir(parent)
        ti._check_root_dir(parent.parent)
    except ti.TrustIdentityError as exc:
        raise Refused(_short(str(exc))) from exc
    old = _read_bytes(target)
    fd, tmp_name = tempfile.mkstemp(prefix=".trust-identity.", dir=str(parent))
    tmp = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, 0o644)
            os.fchown(fd, tm._ROOT_UID, _ROOT_GID)
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        info = os.lstat(tmp)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != tm._ROOT_UID or stat.S_IMODE(info.st_mode) != 0o644:
            raise Refused(f"temp record {tmp} is not a regular root-owned 0644 file")
        back = tmp.read_text(encoding="utf-8")
        if back != text or ti.parse_record(back) != rec:
            raise Refused(f"temp record {tmp} does not parse back to the record being written")
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    try:
        landed = ti.read_record()
        if landed != rec:
            raise Refused("the record that landed does not read back as the record written")
    except (ti.TrustIdentityError, Refused) as exc:
        if old is None:
            target.unlink(missing_ok=True)
        else:
            rtmp = target.with_name(".trust-identity.restore")
            rtmp.write_bytes(old)
            os.chmod(rtmp, 0o644)
            os.chown(rtmp, tm._ROOT_UID, _ROOT_GID)
            os.replace(rtmp, target)
        raise Refused(f"{_short(str(exc))}; the previous record state was restored") from exc
    dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


# ── commands ───────────────────────────────────────────────────────────────

def cmd_precheck(a) -> int:
    old, bad = _old_record()
    if bad is not None:
        print(f"INVALID: {_short(bad)}")
        return 11
    if old is None:
        print("ABSENT")
        return 0
    fpr = a.fingerprint or old.trust_fingerprint
    try:
        live = _live(a.home, fpr)
    except ti.TrustIdentityError as exc:
        print("DIFFERS")
        print(f"live tree cannot be read as the recorded one: {exc}")
        return 10
    diffs = ti.diff_records(old, live)
    if diffs:
        print("DIFFERS")
        for d in diffs:
            print(d)
        return 10
    print("MATCH")
    return 0


def cmd_check(a) -> int:
    old, bad = _old_record()
    if bad is not None:
        print("  [FAIL] trust-identity record is invalid (a recorded box refuses on an invalid record, never reads it as absent)")
        print(f"{_BULLET}{_short(bad)}")
        return 1
    if old is None:
        print("  [info] trust-identity record absent (run with --record-trust-identity after the audit)")
        return 4
    fpr = a.fingerprint or old.trust_fingerprint
    try:
        live = _live(a.home, fpr)
    except ti.TrustIdentityError as exc:
        print("  [FAIL] trust-identity record differs: the live trust directories cannot be read as the recorded ones")
        print(f"{_BULLET}{str(exc)[:300]}")
        return 1
    diffs = ti.diff_records(old, live)
    if diffs:
        print("  [FAIL] trust-identity record differs from the live trust directories")
        for d in diffs:
            print(f"{_BULLET}{d}")
        return 1
    print("  [ok]   trust-identity record valid and matches live")
    return 0


def cmd_diff(a) -> int:
    old, bad = _old_record()
    live = _live(a.home, a.fingerprint)
    print("  live (what a new record would say):")
    print("\n".join(_table(live)))
    if bad is not None:
        print(f"  old record: INVALID ({_short(bad)})")
    elif old is None:
        print("  old record: absent")
    else:
        diffs = ti.diff_records(old, live)
        print("  old record -> live:" if diffs else "  old record -> live: no difference")
        for d in diffs:
            print(f"{_BULLET}{d}")
    return 0


class _Audit:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.ok = True

    def emit(self, label: str, problems: list[str], more: int = 0) -> None:
        if not problems:
            self.lines.append(f"  [ok]   {label}")
            return
        self.ok = False
        self.lines.append(f"  [FAIL] {label}")
        self.lines += [f"{_BULLET}{p}" for p in problems[:8]]
        if len(problems) > 8 or more:
            self.lines.append(f"{_BULLET}... and {len(problems) - 8 + more} more")

    def info(self, text: str) -> None:
        self.lines.append(f"  [info] {text}")


def _own_mode_problem(label: str, st: os.stat_result, uids: "set[int]", *, allow_group_w: bool = False) -> Optional[str]:
    mode = stat.S_IMODE(st.st_mode)
    bad_bits = 0o002 if allow_group_w else 0o022
    if st.st_uid not in uids:
        return f"{label} is owned by uid {st.st_uid}, expected {'/'.join(str(u) for u in sorted(uids))}"
    if mode & bad_bits:
        return f"{label} is {'other' if allow_group_w else 'group/other'}-writable (mode {mode:o})"
    return None


def _plain_dir(path: str, label: str) -> "tuple[Optional[os.stat_result], list[str]]":
    try:
        st = os.lstat(path)
    except OSError as exc:
        return None, [f"{label}: cannot stat ({exc})"]
    if not stat.S_ISDIR(st.st_mode):
        return None, [f"{label} is not a plain directory (symlink or other)"]
    return st, []


def _walk(root: str, uids: "set[int]", *, governed_only: bool) -> "tuple[list[str], list[str], int]":
    """(problems, notes, entries seen). Symlinks and special files are always
    problems. Ownership/mode: every entry when not ``governed_only``; only
    the names in ``_GOVERNED_CONST`` (+ ``.sig``) directly under ``root``
    when ``governed_only`` (others become notes)."""
    problems: list[str] = []
    notes: list[str] = []
    seen = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError as exc:
            problems.append(f"{d}: cannot list ({exc})")
            continue
        for e in entries:
            seen += 1
            if seen > _MAX_WALK:
                problems.append(f"more than {_MAX_WALK} entries under {root}; audit truncated")
                return problems, notes, seen
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as exc:
                problems.append(f"{e.path}: cannot stat ({exc})")
                continue
            if stat.S_ISLNK(st.st_mode):
                problems.append(f"{e.path} is a symlink")
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append(e.path)
            elif not stat.S_ISREG(st.st_mode):
                problems.append(f"{e.path} is neither a regular file nor a directory")
                continue
            shaped = not governed_only
            if governed_only and d == root:
                base = e.name[:-4] if e.name.endswith(".sig") else e.name
                shaped = base in _GOVERNED_CONST
            msg = _own_mode_problem(e.path, st, uids)
            if msg:
                (problems if shaped else notes).append(msg)
    return problems, notes, seen


def _seat_problems(mcp_apps: str) -> "tuple[list[str], int]":
    problems: list[str] = []
    no_app_id = 0
    try:
        names = sorted(os.listdir(mcp_apps))
    except OSError as exc:
        return [f"{mcp_apps}: cannot list ({exc})"], 0
    for name in names:
        seat = os.path.join(mcp_apps, name)
        if name.startswith("_") or not os.path.isdir(seat) or os.path.islink(seat):
            continue
        man = os.path.join(seat, "manifest.json")
        if not os.path.lexists(man):
            continue
        try:
            fd = os.open(man, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            problems.append(f"{man}: cannot open ({exc})")
            continue
        try:
            data = os.read(fd, _MAX_MANIFEST + 1)
        finally:
            os.close(fd)
        if not os.path.isfile(man + ".sig"):
            problems.append(f"{man} has no .sig")
        if len(data) > _MAX_MANIFEST:
            problems.append(f"{man} is larger than {_MAX_MANIFEST} bytes")
            continue
        try:
            doc = json.loads(data)
        except ValueError:
            problems.append(f"{man} is not valid JSON")
            continue
        if not isinstance(doc, dict):
            problems.append(f"{man} is not a JSON object")
        elif "app_id" in doc:
            if doc["app_id"] != name:
                problems.append(f"{man} declares app_id {str(doc['app_id'])[:40]!r} but lives in {name!r} (D4.5)")
        else:
            no_app_id += 1
    return problems, no_app_id


def run_audit(home: str, trust_uid: int, operator_uid: int, fingerprint: str) -> "tuple[list[str], bool, str]":
    au = _Audit()
    real = os.path.realpath(home)
    # D4 marker
    p: list[str] = []
    try:
        marker = tm.read_marker()
        if marker is None:
            p.append(f"{tm.marker_path()} is absent")
        else:
            if marker.willow_home != real:
                p.append(f"the marker binds {marker.willow_home}, this box is {real}")
            if marker.trust_owner_uid != trust_uid:
                p.append(f"the marker records trust owner uid {marker.trust_owner_uid}, the installer resolves {trust_uid}")
    except tm.TrustMarkerError as exc:
        p.append(str(exc)[:200])
    au.emit(f"D4 marker {tm.marker_path()} is valid and binds {real} and uid {trust_uid}", p)
    # $WILLOW_HOME
    st, p = _plain_dir(real, "$WILLOW_HOME")
    if st is not None:
        msg = _own_mode_problem(real, st, {operator_uid, 0})
        if msg:
            p.append(msg)
    au.emit(f"$WILLOW_HOME {real} is a plain directory owned by the operator (uid {operator_uid}), not group/other-writable", p)
    # the two trust-owner directories
    for name in ("constitutional", "mcp_apps"):
        path = os.path.join(real, name)
        st, p = _plain_dir(path, name + "/")
        if st is not None:
            msg = _own_mode_problem(path, st, {trust_uid})
            if msg:
                p.append(msg)
        au.emit(f"{name}/ is a plain directory owned by the trust owner (uid {trust_uid}), not group/other-writable", p)
    # manifest_grants/: operator-owned; the trust owner's rwx ACL raises the
    # group bits to the ACL mask, so only the other-write bit is a signal.
    mg = os.path.join(real, "manifest_grants")
    st, p = _plain_dir(mg, "manifest_grants/")
    if st is not None:
        msg = _own_mode_problem(mg, st, {operator_uid}, allow_group_w=True)
        if msg:
            p.append(msg)
        for child in ("pending", "done", "failed"):
            cst, cp = _plain_dir(os.path.join(mg, child), f"manifest_grants/{child}/")
            p += cp
    au.emit(f"manifest_grants/ and its pending/ done/ failed/ are plain directories owned by the operator (uid {operator_uid}), not other-writable", p)
    # trees
    uids = {trust_uid, 0}
    cpath = os.path.join(real, "constitutional")
    if os.path.isdir(cpath) and not os.path.islink(cpath):
        p, notes, n = _walk(cpath, uids, governed_only=True)
        au.emit(f"constitutional/ ({n} entries): no symlinks; the governed files (trust.env, pre-approved.json, syscall-table.json, frank_head_anchor.json and their .sig) are trust-owner or root owned and not group/other-writable", p)
        for note in notes[:4]:
            au.info(f"not a governed file (not failed): {note}")
    apps = os.path.join(real, "mcp_apps")
    if os.path.isdir(apps) and not os.path.islink(apps):
        p, _notes, n = _walk(apps, uids, governed_only=False)
        au.emit(f"mcp_apps/ ({n} entries, the seats, _federation, _net_leases, _identity_bindings, ...): no symlinks, every entry trust-owner or root owned and not group/other-writable (the D4.5/F1 reader shape)", p)
        p, no_app_id = _seat_problems(apps)
        au.emit("every seat manifest has its .sig, parses, and does not declare another seat's app_id (D4.5)", p)
        if no_app_id:
            au.info(f"{no_app_id} manifest(s) declare no app_id (allowed under the marker for now, operator ruling Q47)")
    # trust.env
    tenv = os.path.join(real, "constitutional", "trust.env")
    p = []
    got = ""
    try:
        fd = os.open(tenv, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            tst = os.fstat(fd)
            body = os.read(fd, 4096).decode("utf-8", "replace")
        finally:
            os.close(fd)
        for line in body.splitlines():
            m = _FPR_LINE.match(line)
            if m:
                got = m.group(1).upper()
        if not got:
            p.append("it carries no 40-hex WILLOW_PGP_FINGERPRINT line")
        elif fingerprint and got != fingerprint.upper():
            p.append(f"it names {got}, the installer resolved {fingerprint.upper()}")
        if not stat.S_ISREG(tst.st_mode):
            p.append("it is not a regular file")
    except OSError as exc:
        p.append(f"cannot open it ({exc})")
    au.emit("constitutional/trust.env is a regular file naming one 40-hex trust fingerprint", p)
    # identity as found
    snapshot = ""
    try:
        rec = _live(real, fingerprint or got or "0" * 40)
        snapshot = snapshot_of(rec)
        au.info("identity found (what a record would pin):")
        au.lines += _table(rec)
    except ti.TrustIdentityError as exc:
        au.emit("the identity of $WILLOW_HOME and the recorded directories can be read", [str(exc)[:300]])
    return au.lines, au.ok, snapshot


def cmd_audit(a) -> int:
    lines, ok, snap = run_audit(a.home, a.trust_owner_uid, a.operator_uid, a.fingerprint)
    print("\n".join(lines))
    if snap:
        print(f"snapshot={snap}")
    return 0 if ok else 1


def _tty_confirm(token: str) -> Optional[str]:
    try:
        tty = open("/dev/tty", "r+")
    except OSError:
        return None
    try:
        tty.write(f"  Type {token} to write the new record (anything else writes nothing): ")
        tty.flush()
        return tty.readline().strip()
    finally:
        tty.close()


def cmd_write(a) -> int:
    live = _live(a.home, a.fingerprint)
    old, bad = _old_record()
    if a.mode == "first":
        if old is not None or bad is not None:
            raise Refused("a trust-identity record already exists (valid or not); the first-record flag is only for a box with none -- use --re-record-trust-identity")
        if a.expect_snapshot and snapshot_of(live) != a.expect_snapshot:
            raise Refused("the identity of $WILLOW_HOME or a recorded directory changed since the audit ran (snapshot differs); nothing written. Rerun")
    elif a.mode == "rewrite":
        if bad is not None:
            raise Refused(f"the existing record is invalid ({_short(bad)}); nothing written -- use --re-record-trust-identity after investigating")
        if old is None:
            raise Refused("there is no record to keep current")
        allowed = ["trust_fingerprint differs"] if a.allow_fingerprint_change else []
        unexpected = [d for d in ti.diff_records(old, live) if d not in allowed]
        if unexpected:
            raise Refused("the live trust directories differ from the record (" + "; ".join(unexpected) + "); nothing written -- investigate, then --re-record-trust-identity")
        if ti.render_record(old) == ti.render_record(live):
            print("  trust-identity record already current -- not rewritten")
            return 0
    else:  # rerecord
        if old is None and bad is None:
            raise Refused("there is no trust-identity record to re-record; the first record is written by a plain install with --record-trust-identity")
        token = confirm_token(live)
        given = a.confirm
        if given is None:
            given = _tty_confirm(token)
            if given is None:
                print(f"  confirmation required: the new record's token is {token}")
                print("  no terminal to type it on: after reading the diff and audit above, rerun with --confirm " + token)
                return 3
        if given != token:
            raise Refused("the confirmation does not match the token of the record about to be written; nothing written")
    install_record(live)
    print(f"  wrote {ti.record_path()} (root:root 0644): {snapshot_of(live)}")
    return 0


# ── cli ────────────────────────────────────────────────────────────────────

def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, *, fpr_required: bool) -> None:
        sp.add_argument("--home", required=True)
        sp.add_argument("--fingerprint", default="", required=fpr_required)

    common(sub.add_parser("precheck"), fpr_required=False)
    common(sub.add_parser("check"), fpr_required=False)
    common(sub.add_parser("diff"), fpr_required=True)
    au = sub.add_parser("audit")
    common(au, fpr_required=False)
    au.add_argument("--trust-owner-uid", type=int, required=True)
    au.add_argument("--operator-uid", type=int, required=True)
    w = sub.add_parser("write")
    common(w, fpr_required=True)
    w.add_argument("--mode", choices=("first", "rewrite", "rerecord"), required=True)
    w.add_argument("--expect-snapshot", default="")
    w.add_argument("--allow-fingerprint-change", action="store_true")
    w.add_argument("--confirm", default=None)
    return p


def main(argv: "list[str] | None" = None) -> int:
    a = _parser().parse_args(argv)
    try:
        return {
            "precheck": cmd_precheck, "check": cmd_check, "diff": cmd_diff,
            "audit": cmd_audit, "write": cmd_write,
        }[a.cmd](a)
    except (Refused, ti.TrustIdentityError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
