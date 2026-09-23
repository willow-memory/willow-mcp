"""PGP detached-signature verification (operator trust root).

Fail-closed when WILLOW_PGP_FINGERPRINT is set. Ported from willow-2.0/sap/core/gate.py
without dev_bypass. See docs/design/pgp-and-persona.md.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
import re
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Iterator

_FP_RE = re.compile(r"^[A-F0-9]{40}$", re.IGNORECASE)


class PgpFingerprintConflict(RuntimeError):
    """The process environment and ``$WILLOW_HOME/env`` disagree on
    ``WILLOW_PGP_FINGERPRINT``. This is exactly the split brain measured
    2026-09-23 (dispatch B291C0C7): install.sh rewrote the trust owner's
    key into ``$WILLOW_HOME/env``, a per-file pin elsewhere (a systemd
    drop-in, a manifest-grant env file) kept the old one, and whichever
    file a given process happened to read decided whether it trusted the
    register. ``$WILLOW_HOME/env`` is the one source of truth; a process
    environment that disagrees with it is never silently preferred or
    silently ignored — it is refused, loudly, naming both values and both
    sources, the first time anything asks what the fingerprint is."""


#: Guards ``_env_file_cache`` — ``expected_fingerprint()`` is hot (called
#: on every trust-owner-owned read), so the ``$WILLOW_HOME/env`` file is
#: cached by (path, mtime, size) rather than re-read and re-parsed on
#: every call. Keyed on a stat, not just "read once": a rotation (or a
#: test pointing WILLOW_HOME elsewhere) changes the stat, so the cache
#: self-invalidates without any caller needing to know to clear it.
_env_file_cache_lock = threading.Lock()
_env_file_cache: tuple[str, float, int, str] | None = None


def _home_env_path() -> Path:
    from . import paths

    return paths.willow_home() / "env"


def _read_home_env_fingerprint() -> str:
    """``WILLOW_PGP_FINGERPRINT=`` as set in ``$WILLOW_HOME/env``, or ``""``
    when the file is absent, unreadable, or carries no such line. Cached by
    (path, mtime, size); see the module-level lock/cache docstring."""
    global _env_file_cache
    path = _home_env_path()
    try:
        st = path.stat()
    except OSError:
        with _env_file_cache_lock:
            _env_file_cache = None
        return ""
    key = (str(path), st.st_mtime, st.st_size)
    with _env_file_cache_lock:
        cached = _env_file_cache
        if cached is not None and cached[:3] == key:
            return cached[3]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    value = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, raw_value = stripped.partition("=")
        if name.strip() != "WILLOW_PGP_FINGERPRINT":
            continue
        value = raw_value.strip().strip("'").strip('"').upper()
    with _env_file_cache_lock:
        _env_file_cache = (*key, value)
    return value


def expected_fingerprint() -> str:
    """The one trusted signer fingerprint, resolved with exactly one
    source of truth: ``$WILLOW_HOME/env``. The process environment is
    consulted too — a caller may set ``WILLOW_PGP_FINGERPRINT`` directly
    (tests; a CLI invoked before the home env is written) — but only to
    confirm it AGREES with the file when the file also has a value.
    Three states, never collapsed into each other:

    * unset — neither source has a value: returns ``""``.
    * set — exactly one source has a value, or both agree: returns it.
    * conflicting — both sources have a value and they differ: raises
      :class:`PgpFingerprintConflict` rather than picking one. Silently
      preferring either side is exactly how the 2026-09-23 lockout
      happened — the broker trusted its own pin while the register was
      re-signed under the box's new one.
    """
    env_value = (os.environ.get("WILLOW_PGP_FINGERPRINT") or "").strip().upper()
    file_value = _read_home_env_fingerprint()
    if env_value and file_value and env_value != file_value:
        raise PgpFingerprintConflict(
            "WILLOW_PGP_FINGERPRINT conflict: the process environment says "
            f"{env_value} but {_home_env_path()} says {file_value} — "
            "$WILLOW_HOME/env is the one source of truth and these must "
            "agree; refusing rather than guessing which one is right. Fix "
            "the stale pin (see INSTALL.md --check) and retry."
        )
    return env_value or file_value


def pgp_enabled() -> bool:
    fp = expected_fingerprint()
    return bool(fp and _FP_RE.match(fp))


def signing_blocked() -> tuple[bool, str]:
    """True when detached signing must not run (Kart sandbox)."""
    if os.environ.get("WILLOW_IN_KART", "").strip():
        return True, (
            "PGP signing is not available inside the Kart bwrap sandbox "
            "(gpg-agent socket unreachable). Run sign-seed from host terminal."
        )
    return False, ""


def sign_detached(file_path: Path, *, local_user: str = "") -> tuple[bool, str]:
    """Create file_path.name.sig via gpg --detach-sign --armor (host-side only).

    ``local_user`` (Loki audit 54E3DFC0, R2): when given, passed as
    ``--local-user <local_user>`` so the signature is minted under THAT
    key specifically — never gpg's ambient default signing key, which may
    belong to a different identity than the fingerprint a reader will
    verify against. Every caller that signs a file another process trusts
    BY FINGERPRINT (the envelope register, a seat manifest, the federation
    registry) should pass ``pgp.expected_fingerprint()`` here; the empty
    default preserves prior behavior for callers that never cared which
    key signed (there are none left after R2, but the default keeps this
    function's signature backward-compatible)."""
    blocked, reason = signing_blocked()
    if blocked:
        return False, reason
    if not file_path.is_file():
        return False, f"file not found: {file_path}"

    sig_path = file_path.parent / f"{file_path.name}.sig"
    try:
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                *(["--local-user", local_user] if local_user else []),
                "--detach-sign",
                "--armor",
                "-o",
                str(sig_path),
                str(file_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return False, "gpg not found on PATH"
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or str(e)).strip()[:200]
        return False, detail or "gpg detach-sign failed"
    except subprocess.TimeoutExpired:
        return False, "gpg detach-sign timed out (30s)"
    except OSError as e:
        return False, f"gpg detach-sign error: {e}"
    return True, str(sig_path)


def export_public_key(fingerprint: str) -> tuple[bytes | None, str]:
    """Export the named public key for verification after sudo changes HOME."""
    try:
        result = subprocess.run(
            ["gpg", "--batch", "--armor", "--export", fingerprint],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except FileNotFoundError:
        return None, "gpg not found on PATH"
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or b"").decode(errors="replace").strip()[:200]
        return None, detail or "gpg public-key export failed"
    except subprocess.TimeoutExpired:
        return None, "gpg public-key export timed out (10s)"
    except OSError as e:
        return None, f"gpg public-key export error: {e}"
    if not result.stdout:
        return None, f"no public key exported for {fingerprint}"
    return result.stdout, "public key exported"


def detached_sig_path(file_path: Path) -> Path:
    """Sibling path of the armored detached signature for `file_path`."""
    return file_path.parent / f"{file_path.name}.sig"


def read_detached_sig_bytes(file_path: Path) -> bytes | None:
    """Return the current `.sig` bytes for `file_path`, or None if absent."""
    sig_path = detached_sig_path(file_path)
    if not sig_path.is_file():
        return None
    return sig_path.read_bytes()


@contextmanager
def signed_pair_lock(file_path: Path, *, exclusive: bool) -> Iterator[None]:
    """Coordinate readers and publishers of a content + detached-signature pair.

    A POSIX rename is atomic for one file, not two.  Locking the containing
    directory lets a publisher replace both siblings while gate readers wait,
    so no cooperating reader can observe a mixed-generation pair.  Directories
    are used as the lock object because replacing either file must not replace
    the inode carrying the lock.
    """
    directory = file_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def restore_signed_content(
    file_path: Path,
    previous_bytes: str | None,
    previous_sig: bytes | None,
) -> None:
    """Undo a write+sign attempt so the trust pair is never left half-applied.

    `gpg --detach-sign --yes -o <sig>` can clobber an existing `.sig` even when
    the sign later fails. Restoring only the content file would leave the
    previous good bytes next to a missing/wrong signature — still denied
    everywhere under enforcement, and worse than the pre-call state. This
    restores both, or removes both when the call created the file.
    """
    sig_path = detached_sig_path(file_path)
    if previous_bytes is None:
        file_path.unlink(missing_ok=True)
        sig_path.unlink(missing_ok=True)
        return
    file_path.write_text(previous_bytes, encoding="utf-8")
    if previous_sig is None:
        sig_path.unlink(missing_ok=True)
    else:
        sig_path.write_bytes(previous_sig)


def verify_detached(
    file_path: Path,
    *,
    fingerprint: str | None = None,
    public_key: bytes | None = None,
) -> tuple[bool, str]:
    """Verify a detached signature against the configured or explicit key.

    ``fingerprint`` is for privilege-separated publication: the unprivileged
    operator process signs first, then passes the expected signer explicitly
    to the trust-owner publisher.  The publisher must not infer "PGP is off"
    merely because sudo intentionally discarded its environment.
    """
    expected = (
        fingerprint.strip().upper()
        if fingerprint is not None
        else expected_fingerprint()
    )
    if not expected:
        return False, "expected PGP fingerprint unset"
    if not _FP_RE.match(expected):
        return False, "expected PGP fingerprint malformed"

    sig_path = detached_sig_path(file_path)
    if not sig_path.is_file():
        return False, f"no signature file: {sig_path.name}"

    verify_prefix = ["gpg"]
    temporary_home = None
    try:
        if public_key is not None:
            temporary_home = tempfile.TemporaryDirectory(prefix="willow-gpg-verify-")
            home = Path(temporary_home.name)
            os.chmod(home, 0o700)
            key_file = home / "operator-public-key.asc"
            key_file.write_bytes(public_key)
            imported = subprocess.run(
                ["gpg", "--batch", "--homedir", str(home), "--import", str(key_file)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if imported.returncode != 0:
                detail = (imported.stderr or imported.stdout or "").strip()[:200]
                return False, detail or "gpg public-key import failed"
            verify_prefix.extend(["--homedir", str(home)])
        result = subprocess.run(
            [
                *verify_prefix,
                "--verify",
                "--status-fd=1",
                str(sig_path),
                str(file_path),
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        return False, "gpg not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "gpg verify timed out (5s)"
    except OSError as e:
        return False, f"gpg verify error: {e}"
    finally:
        if temporary_home is not None:
            temporary_home.cleanup()

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:200]
        return False, detail or "gpg verify failed"

    signer_fp = None
    for line in (result.stdout or "").splitlines():
        if line.startswith("[GNUPG:] VALIDSIG"):
            parts = line.split()
            if len(parts) >= 12:
                signer_fp = parts[11].upper()
                break

    if signer_fp is None:
        excerpt = (result.stdout or "")[:200].replace("\n", " ")
        return False, f"gpg ok but no VALIDSIG in status — {excerpt}"

    if signer_fp != expected:
        return (
            False,
            f"unexpected signer {signer_fp[:16]}... (expected {expected[:16]}...)",
        )
    return True, "signature verified"
