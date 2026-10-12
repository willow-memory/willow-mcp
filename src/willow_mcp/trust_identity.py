"""The root-owned trust-directory identity record and the fd-walk reader
(rename-away hole, option D1; docs/design/d1-trust-dir-identity.md).

D4 (``trust_marker``) makes a missing or foreign-owned ``constitutional/`` a
refusal, but it cannot tell WHICH valid-looking directory it is looking at: a
uid-1000 process that owns ``$WILLOW_HOME`` can rename ``mcp_apps/`` aside and
plant a tree carrying copied, genuinely signed manifests. D1 pins the
identity of the containers in a second root-owned file and reads through file
descriptors that were verified against it.

**Bite 1: this module has NO callers.** Nothing in ``paths``, ``pgp``,
``gate``, ``envelopes`` or ``install.sh`` imports it yet
(``tests/test_trust_identity.py`` guards that, deliberately, until bite 3).

The record, ``/etc/willow-mcp/trust-identity`` (compiled in, never an env
var -- the F-C lever lesson of ``trust_marker``), one ``key=value`` per line,
exactly these seven keys, each once, in any order::

    version=1
    willow_home=<realpath of the provisioned $WILLOW_HOME>
    home=fsid:<hex> ino:<n> uid:<n> mode:<octal>[ igen:<n>]
    dir.constitutional=fsid:<hex> ino:<n> uid:<n> mode:<octal>[ igen:<n>]
    dir.mcp_apps=fsid:<hex> ino:<n> uid:<n> mode:<octal>[ igen:<n>]
    dir.manifest_grants=fsid:<hex> ino:<n> uid:<n> mode:<octal>[ igen:<n>]
    trust_fingerprint=<40 hex>

Three states, never collapsed (INVARIANTS.md section 1): **absent**
(:func:`read_record` returns ``None``), **valid** (an :class:`IdentityRecord`)
and **invalid** (:class:`TrustIdentityError`; never read as absent). A record
with no valid D4 marker, or naming a different ``willow_home`` than the
marker, is invalid.

Identity is ``(fsid, ino)`` -- ``st_dev`` is deliberately not recorded or
compared (design section 5.2: it renumbers across reboots and differs under
overlay). ``uid`` and ``mode`` are compared as recorded. ``igen`` is
``i_generation`` (``FS_IOC_GETVERSION``), best effort: recorded when the
ioctl works, compared only when BOTH the record and the live directory have
one.

The walk (:func:`open_trust_dir`, :func:`open_trust_file`,
:func:`read_trust_bytes`) opens ``/`` and every component with
``O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC``, ``fstat``s each step, compares
``$WILLOW_HOME`` and the first component (a recorded directory) to the
record, and applies the D4 shape (trust-owner or root owned, no group/other
write bit, regular file or directory) to every component below
``constitutional/`` and ``mcp_apps/`` on the ``fstat`` of the fd just opened,
never a second path stat. Bytes are read from the verified fd, so a rename
after the walk cannot redirect the read. The per-component walk is the
reference; below the recorded directory the same steps can be taken through
``openat2(2)`` with ``RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV``
when a cached probe says the kernel allows it, and fall back to the plain
walk (ENOSYS, EPERM, EINVAL, unknown architecture) with identical results.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import logging
import os
import platform
import re
import stat
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import trust_marker

logger = logging.getLogger(__name__)

#: Compiled in. NOT env-overridable (see module docstring). Tests redirect it
#: by monkeypatching ``_RECORD_PATH`` (and ``trust_marker._ROOT_UID``).
_RECORD_PATH = Path("/etc/willow-mcp/trust-identity")

#: Size cap for the record file. The real one is under 1 KiB.
_MAX_RECORD_BYTES = 8192

#: Size cap for a file read through the verified fd (a manifest or sig).
MAX_TRUST_FILE_BYTES = 8 * 1024 * 1024

RECORD_VERSION = "1"

#: The directories directly under ``$WILLOW_HOME`` the record pins. A walk
#: must start at one of these.
RECORDED_DIRS = ("constitutional", "mcp_apps", "manifest_grants")

#: Directories whose children are trust-owner governed (D4 shape applies to
#: every component below them). ``manifest_grants/`` is not: the broker
#: legitimately writes ``pending/`` and ``broker_signing_key`` there (design
#: section 2.3), so below it only kind, symlink and mount-crossing are
#: enforced.
_SHAPE_DIRS = frozenset({"constitutional", "mcp_apps"})


class TrustIdentityError(RuntimeError):
    """The identity record is present but cannot be trusted, or the live tree
    does not match it. Fail closed: callers refuse, they never fall back."""


class TrustIdentityMissing(TrustIdentityError):
    """A directory the record names (``$WILLOW_HOME`` or a recorded child, or
    an ancestor on the way) does not exist. Refused, never re-created
    (operator ruling Q-D1-6)."""


def record_path() -> Path:
    return _RECORD_PATH


# ── data ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DirIdentity:
    fsid: int
    ino: int
    uid: int
    mode: int
    igen: Optional[int] = None

    def render(self) -> str:
        s = f"fsid:{self.fsid:x} ino:{self.ino} uid:{self.uid} mode:{self.mode:o}"
        if self.igen is not None:
            s += f" igen:{self.igen}"
        return s


@dataclass(frozen=True)
class IdentityRecord:
    willow_home: str
    home: DirIdentity
    constitutional: DirIdentity
    mcp_apps: DirIdentity
    manifest_grants: DirIdentity
    trust_fingerprint: str
    version: str = RECORD_VERSION

    def dir_identity(self, name: str) -> DirIdentity:
        if name not in RECORDED_DIRS:
            raise KeyError(name)
        return getattr(self, name)


def render_record(rec: IdentityRecord) -> str:
    """The exact file text for ``rec`` (what bite 2's writer will install)."""
    return (
        f"version={rec.version}\n"
        f"willow_home={rec.willow_home}\n"
        f"home={rec.home.render()}\n"
        f"dir.constitutional={rec.constitutional.render()}\n"
        f"dir.mcp_apps={rec.mcp_apps.render()}\n"
        f"dir.manifest_grants={rec.manifest_grants.render()}\n"
        f"trust_fingerprint={rec.trust_fingerprint}\n"
    )


# ── the record reader ──────────────────────────────────────────────────────

def _bad(reason: str) -> TrustIdentityError:
    return TrustIdentityError(
        f"trust-identity record {_RECORD_PATH} is not trustworthy: {reason}. "
        "This box pins the identity of its trust directories (docs/design/"
        "d1-trust-dir-identity.md), so an untrustworthy record is refused, "
        "never read as 'no record'. A root operator must repair or re-write "
        "it (install.sh --re-record-trust-identity)."
    )


def _check_root_dir(d: Path) -> None:
    try:
        info = os.lstat(d)
    except OSError as exc:
        raise _bad(f"cannot stat parent {d} ({exc})") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise _bad(f"parent {d} is not a plain directory (symlink or other)")
    if info.st_uid != trust_marker._ROOT_UID:
        raise _bad(f"parent {d} is owned by uid {info.st_uid}, not root")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise _bad(f"parent {d} is group- or other-writable")


_DIR_RE = re.compile(
    r"fsid:([0-9a-f]{1,16}) ino:(0|[1-9][0-9]{0,19}) uid:(0|[1-9][0-9]{0,9}) "
    r"mode:([0-7]{1,4})(?: igen:(0|[1-9][0-9]{0,19}))?"
)
_FPR_RE = re.compile(r"[0-9A-Fa-f]{40}")
_KEYS = (
    "version", "willow_home", "home", "dir.constitutional", "dir.mcp_apps",
    "dir.manifest_grants", "trust_fingerprint",
)


def _parse_dir(key: str, value: str) -> DirIdentity:
    m = _DIR_RE.fullmatch(value)
    if m is None:
        raise _bad(f"{key} is not 'fsid:<hex> ino:<n> uid:<n> mode:<octal>[ igen:<n>]'")
    fsid, ino, uid, mode, igen = m.groups()
    return DirIdentity(
        fsid=int(fsid, 16), ino=int(ino), uid=int(uid), mode=int(mode, 8),
        igen=int(igen) if igen is not None else None,
    )


def _valid_home(h: str) -> bool:
    return (
        os.path.isabs(h) and h == os.path.normpath(h) and "\0" not in h
        and h != "/" and "\n" not in h and "\r" not in h
    )


def parse_record(text: str) -> IdentityRecord:
    """Strict parse. No blank lines, no comments, no spaces around ``=``, no
    unknown or repeated keys, a single trailing newline. The only writer is
    ``install.sh`` (fixed format), so leniency would only hide corruption.
    Raises :class:`TrustIdentityError`."""
    if not text or not text.endswith("\n"):
        raise _bad("it is empty or has no trailing newline")
    fields: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        key, sep, value = line.partition("=")
        if not sep or key not in _KEYS:
            raise _bad(f"unrecognised or malformed line {line[:60]!r}")
        if key in fields:
            raise _bad(f"duplicate key {key}")
        fields[key] = value
    if fields.get("version") != RECORD_VERSION:
        raise _bad(f"unknown version {fields.get('version', '(missing)')!r} (this reader understands {RECORD_VERSION})")
    missing = [k for k in _KEYS if k not in fields]
    if missing:
        raise _bad(f"missing key(s) {', '.join(missing)}")
    if not _valid_home(fields["willow_home"]):
        raise _bad("willow_home is not a normalised absolute path")
    if not _FPR_RE.fullmatch(fields["trust_fingerprint"]):
        raise _bad("trust_fingerprint is not 40 hex digits")
    return IdentityRecord(
        willow_home=fields["willow_home"],
        home=_parse_dir("home", fields["home"]),
        constitutional=_parse_dir("dir.constitutional", fields["dir.constitutional"]),
        mcp_apps=_parse_dir("dir.mcp_apps", fields["dir.mcp_apps"]),
        manifest_grants=_parse_dir("dir.manifest_grants", fields["dir.manifest_grants"]),
        trust_fingerprint=fields["trust_fingerprint"].upper(),
    )


def read_record() -> "IdentityRecord | None":
    """``None`` when the record file is absent; an :class:`IdentityRecord`
    when valid; raises :class:`TrustIdentityError` when present-but-invalid,
    including: not a regular file, not root-owned, group/other-writable, a
    parent or grandparent that is not root-owned or is group/other-writable,
    changed between stat and open, oversized, not UTF-8, bad grammar, no
    valid D4 marker, or a ``willow_home`` different from the marker's."""
    p = _RECORD_PATH
    try:
        info = os.lstat(p)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _bad(f"cannot stat it ({exc})") from exc
    if not stat.S_ISREG(info.st_mode):
        raise _bad("it is not a regular file (symlink or other)")
    if info.st_uid != trust_marker._ROOT_UID:
        raise _bad(f"it is owned by uid {info.st_uid}, not root")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise _bad("it is group- or other-writable")
    _check_root_dir(p.parent)
    _check_root_dir(p.parent.parent)
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise _bad(f"cannot open it ({exc})") from exc
    try:
        info2 = os.fstat(fd)
        if (info2.st_ino, info2.st_dev) != (info.st_ino, info.st_dev):
            raise _bad("it changed between stat and open")
        data = os.read(fd, _MAX_RECORD_BYTES + 1)
    except OSError as exc:
        raise _bad(f"cannot read it ({exc})") from exc
    finally:
        os.close(fd)
    if len(data) > _MAX_RECORD_BYTES:
        raise _bad(f"it is larger than {_MAX_RECORD_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _bad("it is not UTF-8 text") from None
    rec = parse_record(text)
    try:
        marker = trust_marker.read_marker()
    except trust_marker.TrustMarkerError as exc:
        raise _bad(f"the D4 marker is not valid ({str(exc)[:200]})") from exc
    if marker is None:
        raise _bad("there is no valid D4 trust-provisioned marker beside it")
    if marker.willow_home != rec.willow_home:
        raise _bad(
            f"willow_home={rec.willow_home} differs from the marker's "
            f"willow_home={marker.willow_home}"
        )
    return rec


def active_record() -> "IdentityRecord | None":
    """The valid record bound to THIS process's home and trust owner, or
    ``None`` when no record exists. Marker first (``trust_marker.
    active_marker``: process home and trust-owner uid cross-checks), then the
    record. Raises :class:`TrustIdentityError` otherwise."""
    rec = read_record()
    if rec is None:
        return None
    try:
        marker = trust_marker.active_marker()
    except trust_marker.TrustMarkerError as exc:
        raise _bad(f"the D4 marker does not bind this process ({str(exc)[:200]})") from exc
    if marker is None or marker.willow_home != rec.willow_home:
        raise _bad("it does not match the active D4 marker")
    return rec


# ── identity of a live directory ───────────────────────────────────────────

def _fs_ioc_getversion() -> int:
    # _IOR('v', 1, long)
    return (2 << 30) | (struct.calcsize("l") << 16) | (ord("v") << 8) | 1


def _get_igen(fd: int) -> Optional[int]:
    """``i_generation`` through ``FS_IOC_GETVERSION``, or ``None`` when the
    filesystem or kernel does not answer. Never raises."""
    try:
        out = fcntl.ioctl(fd, _fs_ioc_getversion(), b"\0" * struct.calcsize("l"))
        return struct.unpack("l", out)[0] & 0xFFFFFFFFFFFFFFFF
    except (OSError, OverflowError, struct.error, ValueError):
        return None


def identity_of(fd: int) -> DirIdentity:
    """The identity of the open directory ``fd`` as the record stores it."""
    st = os.fstat(fd)
    return DirIdentity(
        fsid=os.fstatvfs(fd).f_fsid, ino=st.st_ino, uid=st.st_uid,
        mode=stat.S_IMODE(st.st_mode), igen=_get_igen(fd),
    )


def diff_identity(want: DirIdentity, found: DirIdentity) -> list[str]:
    """Human-readable differences (empty when they match). ``igen`` is
    compared only when both sides carry one."""
    out = []
    if want.fsid != found.fsid:
        out.append(f"fsid {want.fsid:x} -> {found.fsid:x}")
    if want.ino != found.ino:
        out.append(f"ino {want.ino} -> {found.ino}")
    if want.uid != found.uid:
        out.append(f"uid {want.uid} -> {found.uid}")
    if want.mode != found.mode:
        out.append(f"mode {want.mode:o} -> {found.mode:o}")
    if want.igen is not None and found.igen is not None and want.igen != found.igen:
        out.append(f"igen {want.igen} -> {found.igen}")
    return out


# ── the walk ───────────────────────────────────────────────────────────────

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK

# openat2(2)
_RESOLVE_NO_XDEV = 0x01
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_RESOLVE_ALL = (
    _RESOLVE_BENEATH | _RESOLVE_NO_SYMLINKS | _RESOLVE_NO_MAGICLINKS | _RESOLVE_NO_XDEV
)

# openat2 is 437 on every architecture that uses the unified syscall table;
# any machine not listed here has no known number and uses the plain walk
# (mips and alpha use different numbers and are deliberately not guessed).
_SYS_OPENAT2 = {
    "x86_64": 437, "aarch64": 437, "arm64": 437, "armv7l": 437, "armv8l": 437,
    "i386": 437, "i686": 437, "riscv64": 437, "ppc64le": 437, "ppc64": 437,
    "s390x": 437, "loongarch64": 437,
}


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


def _openat2(dir_fd: int, name: str, flags: int) -> int:
    """``openat2(dir_fd, name, {flags, resolve=_RESOLVE_ALL})``. Raises
    ``OSError`` (with errno), or ``OSError(ENOSYS)`` when no syscall number
    is known for this architecture or libc cannot be loaded."""
    nr = _SYS_OPENAT2.get(platform.machine())
    if nr is None:
        raise OSError(errno.ENOSYS, "no openat2 syscall number for this architecture")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        syscall = libc.syscall
    except (OSError, AttributeError) as exc:
        raise OSError(errno.ENOSYS, "libc syscall() unavailable") from exc
    syscall.restype = ctypes.c_long
    how = _OpenHow(flags=flags, mode=0, resolve=_RESOLVE_ALL)
    ctypes.set_errno(0)
    rc = syscall(
        ctypes.c_long(nr), ctypes.c_int(dir_fd), os.fsencode(name),
        ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return int(rc)


_probe_lock = threading.Lock()
_probe_result: Optional[bool] = None


def _probe_openat2() -> bool:
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        fd = _openat2(root, ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        logger.info("openat2 unavailable (%s); trust walk uses per-component opens", exc)
        return False
    finally:
        os.close(root)
    os.close(fd)
    logger.info("openat2 available; trust walk uses RESOLVE_BENEATH below the recorded directory")
    return True


def openat2_available() -> bool:
    """Cached once per process (``reset_openat2_probe`` for tests)."""
    global _probe_result
    with _probe_lock:
        if _probe_result is None:
            _probe_result = _probe_openat2()
        return _probe_result


def reset_openat2_probe() -> None:
    global _probe_result
    with _probe_lock:
        _probe_result = None


def _disable_openat2() -> None:
    global _probe_result
    with _probe_lock:
        _probe_result = False


_FALLBACK_ERRNOS = (errno.ENOSYS, errno.EPERM, errno.EINVAL)


def _open_at(parent_fd: int, name: str, flags: int, use_openat2: bool) -> int:
    if use_openat2:
        try:
            return _openat2(parent_fd, name, flags)
        except OSError as exc:
            if exc.errno not in _FALLBACK_ERRNOS:
                raise
            _disable_openat2()
            logger.info("openat2 refused mid-run (%s); falling back to per-component opens", exc)
    return os.open(name, flags, dir_fd=parent_fd)


def _split_rel(rel: str) -> list[str]:
    if not isinstance(rel, str) or rel.startswith("/") or "\0" in rel:
        raise TrustIdentityError(f"trust path {rel!r} must be relative to $WILLOW_HOME")
    parts = [p for p in rel.split("/")]
    if parts == [""]:
        return []
    if any(p in ("", ".", "..") for p in parts):
        raise TrustIdentityError(f"trust path {rel!r} has an empty, '.' or '..' component")
    return parts


def _refuse_open(exc: OSError, label: str, *, missing_ok: bool) -> Exception:
    if exc.errno == errno.ENOENT:
        if missing_ok:
            return FileNotFoundError(errno.ENOENT, f"{label} does not exist")
        return TrustIdentityMissing(
            f"{label} does not exist; a recorded trust directory that has gone "
            "missing is refused, not re-created (operator ruling Q-D1-6)"
        )
    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
        return TrustIdentityError(f"{label} is a symlink or not the expected kind (refused)")
    if exc.errno == errno.EXDEV:
        return TrustIdentityError(f"{label} crosses a mount point (refused)")
    return TrustIdentityError(f"cannot open {label} safely ({exc})")


def _open_home(rec: IdentityRecord) -> int:
    """A directory fd for ``$WILLOW_HOME``, reached from ``/`` one
    O_NOFOLLOW component at a time and verified against ``home=``."""
    cur = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        walked = ""
        for name in [p for p in rec.willow_home.split("/") if p]:
            walked += "/" + name
            try:
                nxt = os.open(name, _DIR_FLAGS, dir_fd=cur)
            except OSError as exc:
                raise _refuse_open(exc, walked, missing_ok=False) from exc
            os.close(cur)
            cur = nxt
        found = identity_of(cur)
        diffs = diff_identity(rec.home, found)
        if diffs:
            raise TrustIdentityError(
                f"$WILLOW_HOME {rec.willow_home} is not the recorded directory "
                f"({'; '.join(diffs)}). Recorded {rec.home.render()}, found "
                f"{found.render()}. Refusing (D1)."
            )
        return cur
    except BaseException:
        os.close(cur)
        raise


def _check_kind_shape(st: os.stat_result, label: str, *, want_dir: bool,
                      marker, shape: bool) -> None:
    if want_dir and not stat.S_ISDIR(st.st_mode):
        raise TrustIdentityError(f"{label} is not a plain directory (refused)")
    if not want_dir and not stat.S_ISREG(st.st_mode):
        raise TrustIdentityError(f"{label} is not a regular file (refused)")
    if not shape:
        return
    from . import paths

    if stat.S_IMODE(st.st_mode) & 0o022 or st.st_uid not in paths.provisioned_allowed_uids(marker):
        raise TrustIdentityError(
            f"untrusted ownership or permissions on {label} (uid {st.st_uid}, "
            f"mode {stat.S_IMODE(st.st_mode):o}): it must be owned by the "
            f"trust owner ({marker.trust_owner_uid}) or root and not "
            "group/other-writable"
        )


def _walk(rec: IdentityRecord, marker, rel: str, *, want_dir: bool,
          use_openat2: Optional[bool]) -> int:
    """Return an open fd for ``rel`` under ``$WILLOW_HOME``, every step
    verified. The caller closes it. ``use_openat2``: ``None`` = use it when
    the cached probe says so; ``False`` = reference walk; ``True`` = try it
    (still falls back on ENOSYS/EPERM/EINVAL)."""
    parts = _split_rel(rel)
    cur = _open_home(rec)
    try:
        home_st = os.fstat(cur)
        if not parts:
            if not want_dir:
                raise TrustIdentityError("the trust path names $WILLOW_HOME, not a file")
            return cur
        top = parts[0]
        if top not in RECORDED_DIRS:
            raise TrustIdentityError(
                f"{rel!r} is not under a recorded trust directory "
                f"({', '.join(RECORDED_DIRS)})"
            )
        a = openat2_available() if use_openat2 is None else bool(use_openat2)
        shape = top in _SHAPE_DIRS
        parent_dev = home_st.st_dev
        label = rec.willow_home
        for i, name in enumerate(parts):
            last = i == len(parts) - 1
            is_dir = (not last) or want_dir
            label = f"{label}/{name}"
            flags = _DIR_FLAGS if is_dir else _FILE_FLAGS
            try:
                # i == 0 is the recorded directory itself: always the plain
                # open, because it is verified against the record, not the
                # kernel's resolve rules. Below it, openat2 when available.
                nxt = _open_at(cur, name, flags, a and i >= 1)
            except OSError as exc:
                raise _refuse_open(exc, label, missing_ok=i >= 1) from exc
            os.close(cur)
            cur = nxt
            st = os.fstat(cur)
            if st.st_dev != parent_dev:
                raise TrustIdentityError(
                    f"{label} is on a different device than its parent "
                    "(a mount point inside the trusted chain; refused)"
                )
            parent_dev = st.st_dev
            if i == 0:
                found = identity_of(cur)
                diffs = diff_identity(rec.dir_identity(top), found)
                if diffs:
                    raise TrustIdentityError(
                        f"{label} is not the recorded directory ({'; '.join(diffs)}). "
                        f"Recorded {rec.dir_identity(top).render()}, found "
                        f"{found.render()}. Refusing (D1): a planted or restored "
                        "tree has a different inode."
                    )
            _check_kind_shape(st, label, want_dir=is_dir, marker=marker, shape=shape)
        return cur
    except BaseException:
        os.close(cur)
        raise


def open_trust_dir(rec: IdentityRecord, marker, rel: str, *,
                   use_openat2: Optional[bool] = None) -> int:
    """A verified directory fd for ``rel`` (``""`` = ``$WILLOW_HOME``). The
    caller closes it. ``marker`` supplies the trust-owner uid for the D4
    shape. Raises :class:`TrustIdentityError` (or ``FileNotFoundError`` for
    a missing path below a recorded directory)."""
    return _walk(rec, marker, rel, want_dir=True, use_openat2=use_openat2)


def open_trust_file(rec: IdentityRecord, marker, rel: str, *,
                    use_openat2: Optional[bool] = None) -> int:
    """A verified read-only fd for the regular file ``rel``. The caller
    closes it; reads through it name the verified inode whatever happens to
    the path afterwards."""
    return _walk(rec, marker, rel, want_dir=False, use_openat2=use_openat2)


def read_trust_bytes(rec: IdentityRecord, marker, rel: str, *,
                     max_bytes: int = MAX_TRUST_FILE_BYTES,
                     use_openat2: Optional[bool] = None) -> bytes:
    """The bytes of ``rel``, read from the verified fd."""
    fd = open_trust_file(rec, marker, rel, use_openat2=use_openat2)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            total += len(b)
            if total > max_bytes:
                raise TrustIdentityError(f"{rel} is larger than {max_bytes} bytes (refused)")
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


# ── computing a record (no writing) ────────────────────────────────────────

def compute_record(willow_home: "str | os.PathLike[str]", *,
                   trust_fingerprint: str) -> IdentityRecord:
    """The record that describes the live tree under ``willow_home`` (its
    realpath) right now. Pure: reads, never writes. For bite 2's writer and
    ``--check``. ``trust_fingerprint`` is supplied by the caller (the value
    ``trust.env`` carries); it is validated here. Raises
    :class:`TrustIdentityMissing` when ``$WILLOW_HOME`` or a recorded child
    is absent and :class:`TrustIdentityError` for a symlink or a non-
    directory (children are opened O_NOFOLLOW)."""
    if not _FPR_RE.fullmatch(trust_fingerprint or ""):
        raise TrustIdentityError("trust_fingerprint is not 40 hex digits")
    home = os.path.realpath(willow_home)
    if not _valid_home(home):
        raise TrustIdentityError(f"{home!r} is not a usable $WILLOW_HOME path")
    cur = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        walked = ""
        for name in [p for p in home.split("/") if p]:
            walked += "/" + name
            try:
                nxt = os.open(name, _DIR_FLAGS, dir_fd=cur)
            except OSError as exc:
                raise _refuse_open(exc, walked, missing_ok=False) from exc
            os.close(cur)
            cur = nxt
        home_id = identity_of(cur)
        kids: dict[str, DirIdentity] = {}
        for name in RECORDED_DIRS:
            try:
                kfd = os.open(name, _DIR_FLAGS, dir_fd=cur)
            except OSError as exc:
                raise _refuse_open(exc, f"{home}/{name}", missing_ok=False) from exc
            try:
                kids[name] = identity_of(kfd)
            finally:
                os.close(kfd)
    finally:
        os.close(cur)
    return IdentityRecord(
        willow_home=home, home=home_id,
        constitutional=kids["constitutional"], mcp_apps=kids["mcp_apps"],
        manifest_grants=kids["manifest_grants"],
        trust_fingerprint=trust_fingerprint.upper(),
    )


def diff_records(recorded: IdentityRecord, live: IdentityRecord) -> list[str]:
    """``--check``'s table: one line per differing field, empty when the
    live tree matches the record (the fingerprint included)."""
    out = []
    if recorded.willow_home != live.willow_home:
        out.append(f"willow_home {recorded.willow_home} -> {live.willow_home}")
    for label, a, b in (
        ("home", recorded.home, live.home),
        *((n, recorded.dir_identity(n), live.dir_identity(n)) for n in RECORDED_DIRS),
    ):
        out.extend(f"{label}: {d}" for d in diff_identity(a, b))
    if recorded.trust_fingerprint != live.trust_fingerprint:
        out.append("trust_fingerprint differs")
    return out
