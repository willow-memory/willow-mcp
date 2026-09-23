"""PGP detached-signature verification (operator trust root).

Fail-closed when WILLOW_PGP_FINGERPRINT is set. Ported from willow-2.0/sap/core/gate.py
without dev_bypass. See docs/design/pgp-and-persona.md.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
import re
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Iterator

_FP_RE = re.compile(r"^[A-F0-9]{40}$", re.IGNORECASE)

#: dispatch 0CB0C85C (amending E29CCFC7/B291C0C7): a fingerprint is public —
#: only a key's PRIVATE half is a secret. `$WILLOW_HOME/env` (0600, every
#: provider API key) is the wrong home for a value every verifying process
#: needs to read. The one source of truth lives under the same trust-owner-
#: owned directory the active envelope register and syscall table already
#: do, world-readable, writable only by the trust owner — a file the
#: broker's own uid (1000) could rewrite would let the broker choose what
#: it trusts, which is exactly the property a trust root must not have.
#:
#: Rework #3 (dispatch FA4F79AC) routed this through a ``WILLOW_VAULT_BOX``
#: env-var indirection ("the vault"); rework #4 (dispatch 10F9E837, Loki
#: audit 23DE8AA9, F-C) removed it — a broker-settable variable picking
#: which file is authoritative defeats the whole point of a trust anchor,
#: no matter how the file itself is owned/signed. ``paths.trust_config_path()``
#: now resolves purely from ``WILLOW_HOME`` (see that function's own
#: docstring for the full argument and for exactly when the SEPARATE
#: rename-away hole is and is not closed).
_TRUST_CONFIG_NAME = "trust.env"


class PgpFingerprintConflict(RuntimeError):
    """The process environment and the trust-config file
    (:func:`paths.trust_config_path` — ``$WILLOW_HOME/constitutional/trust.env``)
    disagree on ``WILLOW_PGP_FINGERPRINT``. This is exactly the split brain measured
    2026-09-23 (dispatch B291C0C7): install.sh rewrote the trust owner's
    key into the one source of truth, a per-file pin elsewhere (a systemd
    drop-in, a manifest-grant env file) kept the old one, and whichever
    file a given process happened to read decided whether it trusted the
    register. The trust-config file is the one source of truth; a process
    environment that disagrees with it is never silently preferred or
    silently ignored — it is refused, loudly, naming both values and both
    sources, the first time anything asks what the fingerprint is."""


class PgpSourceUnreadable(RuntimeError):
    """The trust-config file could not be trusted as a source of truth —
    it exists but could not be read, its ownership/permissions do not meet
    the trust-root shape, its ``WILLOW_PGP_FINGERPRINT`` value does not
    parse as a fingerprint, or (Loki re-audit 93D0F057, N2) it is simply
    MISSING on a box that has a resolvable trust owner. Loki audit
    A38D41C2, F4: *unreachable is not empty*. Enforcement may be off only
    because the trust owner wrote that down (the file exists, trust-owner-
    owned, with an explicit empty value) — never because something is
    missing, unreadable, malformed, or owned by the wrong uid. The ONLY
    box where a missing file still legitimately means "never configured"
    is one with NO resolvable trust owner at all (Kart, dev, any box that
    never ran ``trust_root_setup``) — there, "off" is the only state that
    could ever have existed."""


#: Guards ``_trust_config_cache`` — ``expected_fingerprint()`` is hot
#: (called on every trust-owner-owned read), so the trust-config file is
#: cached rather than re-read and re-parsed on every call. Keyed on
#: (path, inode, mtime_ns, size) — not just mtime+size (Loki A38D41C2, F9):
#: a same-size rewrite landing within one float-mtime tick, or a different
#: inode reusing the same path, must still invalidate. A rotation (or a
#: test pointing WILLOW_HOME elsewhere) changes this key, so the cache
#: self-invalidates without any caller needing to know to clear it.
_trust_config_cache_lock = threading.Lock()
_trust_config_cache: tuple[str, int, int, int, str] | None = None


def _trust_config_path() -> Path:
    """The one source of truth's path — a thin wrapper over
    :func:`paths.trust_config_path`, a MODULE-LEVEL FUNCTION, never an
    environment variable a caller (including the broker) could point
    somewhere else. Kept as its own function here (rather than every
    caller in this module importing ``paths`` directly) so tests redirect
    the path by monkeypatching THIS function or ``paths.trust_config_path``
    — never by setting an env var, which is exactly the shape Loki's audit
    asked tests avoid."""
    from . import paths

    return paths.trust_config_path()


def _trust_config_ownership_ok(path: Path) -> None:
    """The trust-config file (and its parent) must not be writable by
    anyone but its owner. Ownership itself is checked STRICTLY against the
    trust owner when one can be resolved — Loki re-audit 93D0F057, N2: the
    prior cut also accepted a file owned by THIS PROCESS'S OWN euid, which
    is right for ``paths.trusted_read``'s general shape (an authorized
    root/operator process reading its own files) but wrong here, because
    the process asking "should I enforce PGP?" is routinely the BROKER
    itself (uid 1000) — the one party a trust root must never let certify
    its own trust. A broker-created ``trust.env`` (self-owned) is no
    longer accepted merely because it matches this process's euid.

    When no trust owner can be resolved at all (``paths._trust_owner_uid()``
    is ``None`` — no distinct trust-owner identity exists on this box:
    Kart, a dev sandbox, any single-uid deployment that never ran
    ``trust_root_setup``), there is no meaningful "someone else" to
    require, so self-ownership is accepted — the same carve-out
    ``paths.trusted_read`` already makes for that case.

    No signature check here — unlike ``paths.trusted_read``'s trust-owner-
    plus-signature branch, THIS file is the fingerprint a signature would
    need to verify against, so checking its own signature would be
    circular. Raises :class:`PgpSourceUnreadable` rather than returning a
    bool, so a caller cannot forget to check it."""
    from . import paths

    euid = os.geteuid()
    try:
        parent_info = path.parent.stat()
        info = path.stat()
    except OSError as exc:
        raise PgpSourceUnreadable(
            f"{path}: could not stat it or its parent ({exc}) — refusing "
            "to treat an unstattable trust-config file as unconfigured"
        ) from exc
    if stat.S_IMODE(parent_info.st_mode) & 0o022 or stat.S_IMODE(info.st_mode) & 0o022:
        raise PgpSourceUnreadable(
            f"{path} or its parent directory is group- or other-writable — "
            "refusing to trust a fingerprint file anyone but its owner "
            "could rewrite. Fix the mode (0644 file, 0755 directory, no "
            "wider) and retry."
        )
    trust_owner_uid = paths._trust_owner_uid()
    if trust_owner_uid is not None:
        if info.st_uid != trust_owner_uid:
            raise PgpSourceUnreadable(
                f"{path} is owned by uid {info.st_uid}, not the trust "
                f"owner's uid ({trust_owner_uid}) — refusing to trust it. "
                "This process's own uid is never an acceptable substitute "
                "here, even when it matches: the party asking whether to "
                "enforce PGP must never be able to author its own answer."
            )
    elif info.st_uid != euid:
        raise PgpSourceUnreadable(
            f"{path} is owned by uid {info.st_uid}, and no trust owner is "
            f"configured on this box to compare against (only this "
            f"process's own uid, {euid}, would be acceptable here) — "
            "refusing to trust it."
        )


def _parse_trust_config_text(text: str, *, path: Path) -> str:
    """``WILLOW_PGP_FINGERPRINT=`` as set in the trust-config file's text,
    or ``""`` when no such line is present (or it is present with an
    explicitly empty value — the template shape before a key is first
    generated). Handles an ``export NAME=value`` line (Loki A38D41C2, F4:
    the box's own env files already use export lines; the old parser
    silently missed the key entirely, resolving to "unset" instead of the
    configured value — a fail-open bug, not intended lenience). A
    non-empty value that does not parse as a 40-hex-character fingerprint
    (a stray inline comment glued onto the value, systemd's
    ``EnvironmentFile=`` grammar takes the rest of the line as literal
    value — there is no comment syntax after the ``=``) raises rather than
    silently disabling enforcement."""
    value = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export ") or stripped.startswith("export\t"):
            stripped = stripped[len("export"):].lstrip()
        if "=" not in stripped:
            continue
        name, _, raw_value = stripped.partition("=")
        if name.strip() != "WILLOW_PGP_FINGERPRINT":
            continue
        value = raw_value.strip().strip("'").strip('"')
    if not value:
        return ""
    candidate = value.upper()
    if not _FP_RE.match(candidate):
        raise PgpSourceUnreadable(
            f"WILLOW_PGP_FINGERPRINT in {path} does not look like a "
            f"40-hex-character fingerprint ({value!r}) — refusing to "
            "silently treat a malformed value as 'no key configured'. "
            "This reader takes the whole rest of the line as the value "
            "(no inline-comment syntax); check for a stray trailing "
            "comment or stray whitespace and retry."
        )
    return candidate


def _trust_config_dir_already_provisioned(dir_path: Path) -> bool:
    """Is the trust-config file's own directory (``$WILLOW_HOME/
    constitutional/`` — :func:`paths.trust_config_path`) ITSELF already
    trust-owner-owned — the signal that install.sh's step 1 has
    provisioned trust for THIS ``$WILLOW_HOME`` specifically, as opposed
    to a trust owner merely existing SOMEWHERE on the host.

    Loki re-audit 93D0F057, N2: keying "trust.env should exist" off
    "``paths._trust_owner_uid()`` resolves to something" is too broad — a
    real ``willow-operator`` account can exist on a box (or in a sandbox
    that mirrors one) whose test fixtures never touch this directory at
    all, and every one of those would start raising for a directory that
    was simply never meant to hold a trust file. Keying off THIS
    directory's own ownership is local to the ``$WILLOW_HOME`` actually in
    play, matching how install.sh actually provisions trust (chown this
    directory to the trust owner, before anything writes trust.env into
    it).

    Returns ``False`` (never provisioned here) on any stat failure —
    including "does not exist at all", which is legitimate bootstrap, not
    an error to surface from a probe function."""
    from . import paths

    trust_owner_uid = paths._trust_owner_uid()
    if trust_owner_uid is None:
        return False
    try:
        return dir_path.stat().st_uid == trust_owner_uid
    except OSError:
        return False


def _read_trust_config_fingerprint() -> str:
    """``WILLOW_PGP_FINGERPRINT=`` from the trust-config file. Three
    states, never collapsed (Loki A38D41C2 F4; tightened by Loki 93D0F057
    N2 — "enforcement may be off only because the trust owner wrote that
    down, never because something is missing"):

    * the file does not exist, and ``constitutional/`` itself has not
      been provisioned for trust (see
      :func:`_trust_config_dir_already_provisioned`) — legitimate
      bootstrap: this ``$WILLOW_HOME`` has never been through
      install.sh's step 1 at all. Returns ``""``.
    * the file does not exist, but ``constitutional/`` IS already
      trust-owner-owned — install.sh's step 1 has run against this exact
      ``$WILLOW_HOME``, and its later step always writes trust.env (with
      a real fingerprint, or an explicit empty value as the trust owner's
      own deliberate "no enforcement" statement). Its absence now means
      either install stopped between those two steps, or something
      removed it after — raises :class:`PgpSourceUnreadable` rather than
      silently disabling enforcement.

      RESIDUAL GAP, named plainly rather than hidden — the broker owns
      ``$WILLOW_HOME`` itself (mode 700), so it can rename ``constitutional/``
      away ENTIRELY (a rename needs write only on the PARENT, which the
      broker's uid holds) and put an empty, self-owned directory of the
      same name back — at that point THIS check also sees "never
      provisioned" and returns unset. No purely local, file-permission-
      based scheme can close that: the parent the broker owns is above
      anything trust.env's own mode could ever protect. Rework #3
      (dispatch FA4F79AC) tried routing the whole file through a SEPARATE,
      independently-configured location (``WILLOW_VAULT_BOX``) to escape
      this — rework #4 (dispatch 10F9E837, Loki audit 23DE8AA9, F-C)
      reverted that: a location the broker's own process env can steer is
      a worse problem than the one it was trying to solve (a reader could
      be made to trust a DIFFERENT file than install.sh wrote, not merely
      fail to escape a rename). What WOULD close the rename-away hole is a
      marker the broker's uid cannot remove or recreate — a second signal
      living outside the broker's own writable tree entirely, established
      by making ``$WILLOW_HOME`` ITSELF resolve to a root-provisioned
      location for every process that shares this box (not a second,
      independently-set variable layered on top of it). That is a larger
      deploy/architecture change, out of this dispatch's scope; recorded
      as a gap rather than silently left unfixed.
    * the file exists but cannot be trusted (unreadable, wrong ownership/
      permissions, or a malformed value) — raises
      :class:`PgpSourceUnreadable`.
    * the file exists, is trustworthy, and has a fingerprint (or an
      explicitly empty value — the trust owner's own written statement
      that enforcement is off, install.sh's template shape before a key
      is first generated) — returns it (or ``""`` for the empty-value
      case, which is legitimate, not a parse failure: the trust owner
      wrote it down).

    Cached by (path, inode, mtime_ns, size); see the module-level
    lock/cache docstring for why those four fields.
    """
    global _trust_config_cache
    path = _trust_config_path()
    if not path.exists():
        with _trust_config_cache_lock:
            _trust_config_cache = None
        if _trust_config_dir_already_provisioned(path.parent):
            raise PgpSourceUnreadable(
                f"{path} does not exist, but {path.parent} is already "
                "trust-owner-owned — this $WILLOW_HOME has been through "
                "install's trust provisioning step, which always writes "
                "this file (even with an explicit empty value for "
                "deliberate no-enforcement). Its absence now means "
                "either install stopped partway through, or something "
                "removed it after. Refusing to treat a missing file as a "
                "legitimate 'off' either way: enforcement is off ONLY "
                "when the trust owner wrote that down in this file, "
                "never because it is absent. Run install.sh (or restore "
                "constitutional/) and retry."
            )
        return ""
    _trust_config_ownership_ok(path)  # raises PgpSourceUnreadable, never silent
    try:
        st = path.stat()
    except OSError as exc:
        raise PgpSourceUnreadable(f"{path}: {exc}") from exc
    key = (str(path), st.st_ino, st.st_mtime_ns, st.st_size)
    with _trust_config_cache_lock:
        cached = _trust_config_cache
        if cached is not None and cached[:4] == key:
            return cached[4]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PgpSourceUnreadable(
            f"{path} exists but is unreadable ({exc}) — the one source of "
            "truth for WILLOW_PGP_FINGERPRINT could not be read; refusing "
            "to silently treat this as 'no key configured'. Fix the "
            "file's permissions and retry."
        ) from exc
    value = _parse_trust_config_text(text, path=path)
    with _trust_config_cache_lock:
        _trust_config_cache = (*key, value)
    return value


def expected_fingerprint() -> str:
    """The one trusted signer fingerprint, resolved with exactly one
    source of truth: :func:`paths.trust_config_path`
    (``$WILLOW_HOME/constitutional/trust.env``, resolved from
    ``WILLOW_HOME`` alone — no other env var, see that function's
    docstring) — a trust-owner-owned, world-readable file (dispatch
    0CB0C85C: a
    fingerprint is public; only a key's private half is a secret, so the
    one source of truth does not need to live beside provider API keys in
    a 0600 file the trust-owner apply unit could never read). The process
    environment is consulted too — a caller may set
    ``WILLOW_PGP_FINGERPRINT`` directly (tests; a CLI invoked before the
    trust-config file is written) — but only to confirm it AGREES with the
    file when the file also has a value. Three states, never collapsed
    into each other:

    * unset — neither source has a value: returns ``""``.
    * set — exactly one source has a value, or both agree: returns it.
    * conflicting — both sources have a value and they differ: raises
      :class:`PgpFingerprintConflict` rather than picking one. Silently
      preferring either side is exactly how the 2026-09-23 lockout
      happened — the broker trusted its own pin while the register was
      re-signed under the box's new one.

    A trust-config file that exists but cannot be trusted (unreadable,
    wrong ownership, malformed value) raises :class:`PgpSourceUnreadable`
    rather than resolving as unset — *unreachable is not empty* (Loki
    A38D41C2, F4). The SAME rule applies to a malformed PROCESS-env value
    (Loki 93D0F057, N6: ``WILLOW_PGP_FINGERPRINT='<fpr>  # x'`` in the
    environment used to return that raw, non-hex string, which
    :func:`pgp_enabled`'s own regex check then silently rejected —
    enforcement off, with nothing raised anywhere. A non-empty process-env
    value that does not parse as a fingerprint now raises here too, before
    it ever reaches a truthiness check that could quietly discard it.
    """
    env_value = (os.environ.get("WILLOW_PGP_FINGERPRINT") or "").strip().upper()
    if env_value and not _FP_RE.match(env_value):
        raise PgpSourceUnreadable(
            f"WILLOW_PGP_FINGERPRINT in the process environment does not "
            f"look like a 40-hex-character fingerprint ({env_value!r}) — "
            "refusing to silently treat a malformed value as 'no key "
            "configured'."
        )
    file_value = _read_trust_config_fingerprint()
    if env_value and file_value and env_value != file_value:
        raise PgpFingerprintConflict(
            "WILLOW_PGP_FINGERPRINT conflict: the process environment says "
            f"{env_value} but {_trust_config_path()} says {file_value} — "
            f"{_trust_config_path()} is the one source of truth and these "
            "must agree; refusing rather than guessing which one is "
            "right. Fix the stale pin (see INSTALL.md --check-signatures) "
            "and retry — for a stdio-attached desk seat, this usually "
            "means a pin in this project's .mcp.json (env.WILLOW_PGP_"
            "FINGERPRINT) that the operator must remove and reconnect."
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
