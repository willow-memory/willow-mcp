"""The root-owned "trust provisioned" marker (rename-away hole, D4).

Loki audit D06A0EF3: ``$WILLOW_HOME`` is owned by the broker's uid, so any
uid-1000 process can rename ``constitutional/`` aside and plant its own
directory. Before this module, an absent ``trust.env`` in a directory that
was not trust-owner-owned meant "legitimate bootstrap, enforcement off", so a
rename-away turned PGP enforcement off for every reader on the box.

The close (docs/design/rename-away-hole.md, option D4) is a fact the broker
cannot erase: ``/etc/willow-mcp/trust-provisioned``, written by ``install.sh``
as root once trust is provisioned. Format, one ``key=value`` per line::

    willow_home=<realpath of the provisioned $WILLOW_HOME>
    trust_owner_uid=<uid of the trust owner>

Three states, never collapsed (INVARIANTS.md section 1):

* **absent** -- no marker file: today's behaviour exactly (fresh boxes,
  dev boxes, tests). :func:`active_marker` returns ``None``.
* **valid** -- a root-owned regular file, not group/other-writable, whose
  two parent directories are root-owned and not group/other-writable.
* **invalid** -- anything else that is present or unstattable (symlink,
  wrong owner, wide mode, bad parent, unreadable, malformed). Raises
  :class:`TrustMarkerError`; it is never read as "absent".

Home binding: the marker binds trust to the ``$WILLOW_HOME`` it names. A
process whose ``$WILLOW_HOME`` realpath differs, on a host that carries a
valid marker, is refused (:class:`TrustMarkerError`) on trust-sensitive
reads rather than silently run unenforced. Tests and dev boxes are
unaffected on an unprovisioned machine; on a provisioned machine a
different home is a different box, and there is no override (an override
the broker could set would be the F-C lever again).

The marker path is a compiled-in constant. Tests redirect it by
monkeypatching ``_MARKER_PATH`` (and ``_ROOT_UID``), never an env var.
"""

from __future__ import annotations

import logging
import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

#: Compiled in. NOT env-overridable: a broker-settable marker path is the
#: F-C lever (Loki 23DE8AA9) in a new place.
_MARKER_PATH = Path("/etc/willow-mcp/trust-provisioned")

#: The uid that must own the marker and its parents. Test seam only.
_ROOT_UID = 0


#: The uid (besides the trust owner) whose ownership a governance input may
#: carry on a provisioned box. Separate from ``_ROOT_UID`` so a test running
#: as root can still model "owned by the broker's own euid". Test seam only.
_GOVERNANCE_ROOT_UID = 0


class TrustMarkerError(RuntimeError):
    """The trust-provisioned marker is present but cannot be trusted, or it
    binds trust to a different ``$WILLOW_HOME``, or the trust owner it
    records is not the trust owner this process resolves. Fail closed:
    callers refuse, they never fall back to the bootstrap behaviour."""


@dataclass(frozen=True)
class TrustMarker:
    willow_home: str
    trust_owner_uid: int


def marker_path() -> Path:
    return _MARKER_PATH


def _bad(reason: str) -> TrustMarkerError:
    return TrustMarkerError(
        f"trust-provisioned marker {_MARKER_PATH} is not trustworthy: {reason}. "
        "This box was provisioned for rename-away protection (Loki D06A0EF3, "
        "docs/design/rename-away-hole.md D4), so an untrustworthy marker is "
        "refused, never read as 'not provisioned'. A root operator must "
        "repair or re-write it (run deploy/manifest-grant/install.sh as root)."
    )


def _check_root_dir(d: Path) -> None:
    try:
        info = os.lstat(d)
    except OSError as exc:
        raise _bad(f"cannot stat parent {d} ({exc})") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise _bad(f"parent {d} is not a plain directory (symlink or other)")
    if info.st_uid != _ROOT_UID:
        raise _bad(f"parent {d} is owned by uid {info.st_uid}, not root")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise _bad(f"parent {d} is group- or other-writable")


def _parse(text: str) -> TrustMarker:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip()
    home = fields.get("willow_home", "")
    uid_raw = fields.get("trust_owner_uid", "")
    if not home or not os.path.isabs(home):
        raise _bad("willow_home is missing or not an absolute path")
    try:
        uid = int(uid_raw)
    except ValueError:
        raise _bad("trust_owner_uid is missing or not an integer") from None
    if uid < 0:
        raise _bad("trust_owner_uid is negative")
    return TrustMarker(willow_home=home, trust_owner_uid=uid)


def read_marker() -> "TrustMarker | None":
    """``None`` when the marker is absent; a :class:`TrustMarker` when valid;
    raises :class:`TrustMarkerError` when present-but-invalid."""
    p = _MARKER_PATH
    try:
        info = os.lstat(p)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _bad(f"cannot stat it ({exc})") from exc
    if not stat.S_ISREG(info.st_mode):
        raise _bad("it is not a regular file (symlink or other)")
    if info.st_uid != _ROOT_UID:
        raise _bad(f"it is owned by uid {info.st_uid}, not root")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise _bad("it is group- or other-writable")
    _check_root_dir(p.parent)
    _check_root_dir(p.parent.parent)
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise _bad(f"cannot open it ({exc})") from exc
    try:
        info2 = os.fstat(fd)
        if (info2.st_ino, info2.st_dev) != (info.st_ino, info.st_dev):
            raise _bad("it changed between stat and open")
        data = os.read(fd, 4096)
    except OSError as exc:
        raise _bad(f"cannot read it ({exc})") from exc
    finally:
        os.close(fd)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _bad("it is not UTF-8 text") from None
    return _parse(text)


def active_marker() -> "TrustMarker | None":
    """The valid marker bound to THIS process's ``$WILLOW_HOME``, or ``None``
    when no marker exists. Raises :class:`TrustMarkerError` when the marker
    is invalid, names a different home, or its trust-owner uid disagrees
    with ``paths._trust_owner_uid()`` (cross-check)."""
    marker = read_marker()
    if marker is None:
        return None
    from . import paths

    home = os.path.realpath(paths.willow_home())
    if home != marker.willow_home:
        raise TrustMarkerError(
            f"trust-provisioned marker {_MARKER_PATH} binds trust to "
            f"$WILLOW_HOME={marker.willow_home}, but this process resolves "
            f"$WILLOW_HOME={home}. A provisioned host does not run trust-"
            "sensitive reads against a different home unenforced (Loki "
            "D06A0EF3); refusing. Point WILLOW_HOME at the provisioned home, "
            "or have a root operator re-provision."
        )
    resolved = paths._trust_owner_uid()
    if resolved != marker.trust_owner_uid:
        raise TrustMarkerError(
            f"trust-provisioned marker {_MARKER_PATH} records trust owner "
            f"uid {marker.trust_owner_uid}, but this process resolves the "
            f"trust owner as {resolved!r} -- refusing (Loki D06A0EF3). "
            "A root operator must re-provision (install.sh)."
        )
    return marker


# ── env levers (Q37) ──────────────────────────────────────────────────────

_logged_levers: set[str] = set()
_logged_lock = threading.Lock()


def trust_input_env(name: str) -> str:
    """The stripped value of env lever ``name`` for a TRUST input, or ``""``.

    With a valid marker for this home the lever is IGNORED (returns ``""``,
    so the caller uses its default path under ``$WILLOW_HOME``) and a loud
    error line is logged once per process per variable. Without a marker the
    lever is honoured exactly as before. An invalid marker, or one bound to
    another home, raises :class:`TrustMarkerError` (only reached when the
    lever is set, so an unset lever stays free)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return ""
    if active_marker() is None:
        return raw
    with _logged_lock:
        first = name not in _logged_levers
        _logged_levers.add(name)
    if first:
        logger.error(
            "%s is set (%r) but this host carries a valid trust-provisioned "
            "marker (%s): the variable is IGNORED for trust inputs and the "
            "default path under $WILLOW_HOME is used (Loki D06A0EF3 / "
            "operator ruling Q37). Unset it.",
            name, raw, _MARKER_PATH,
        )
    return ""
