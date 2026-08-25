"""willow_mcp.keyring — which key attests for which operator, and which no longer do.

The gap this closes (see ``docs/design/pgp-and-persona.md`` §1 and
``docs/design/human-orchestrator.md``): everything about trust in willow-mcp's
attribution surface today is rigorous except *who*. ``WILLOW_PGP_FINGERPRINT``
is singular — one blessed operator key for the whole deployment — so a valid
signature on a session sidecar proves the key was present and nothing about
which operator was in the seat. ``WILLOW_HUMAN_ORCHESTRATOR=1`` is an env-var
flag on the MCP host process, not an act of the human it purports to name. And
``sessions/willow-{id}.json`` carries no operator identity at all: a session
record knows its ``app_id`` but not its verifier.

This module is the willow-side port of ``nestor/keyring.py`` (IDEAS §5.8,
decisions ``0074`` / ``0077`` / ``0078``). One key per verifier — ``rita``'s
sessions are attested with ``rita``'s key, so a valid signature over
``(app_id, session_id, "rita", attested_at)`` is evidence about *rita* rather
than about the deployment. Someone holding ``sam``'s key cannot produce one,
and a server-side process holding neither cannot produce any.

Same three properties Nestor's port docstring names, applied to willow's
attestation seat instead of Nestor's seal:

* **It is opt-in, and the old behavior is untouched without it.** No keyring
  configured means the existing PGP-fingerprint + env-var path stays exactly
  as before (``pgp.py``, ``human_session.py``). A keyring is installed with
  :func:`set_keyring`, or found at ``WILLOW_KEYRING``.
* **With a keyring installed, an unknown name cannot attest.** That is the
  entire point: attesting as a verifier the keyring does not know raises
  :class:`UnknownVerifierError` before the session file is written. Sessions
  that predate the keyring are the migration case (see the ``legacy_key``
  seam), and PR3 of the identity-in-session plan wires client-signing to
  complete the picture.
* **Revocation asks one question, because the answer genuinely differs.** A
  signature carries no timestamp, so it cannot tell "attested by rita last
  March" from "forged last night by whoever took rita's key." Willow will not
  pretend otherwise, so :meth:`Keyring.revoke` makes the operator say which
  happened:

  * ``compromised=False`` — *rita left, rotate the key.* Nobody else ever held
    it, so everything it attested is still a session rita really opened. Those
    attestations keep serving; the key simply cannot make new ones.
  * ``compromised=True`` — *the key was taken.* Nothing it signed can be told
    apart from something the thief signed, so **none of it serves.** The rows
    are not deleted; PR4 wires them into a ``sessions_unverifiable`` surface
    mirroring ``nestor.curator.Curator.unverifiable``.

Guessing between those two would be wrong every time — silently retiring a
departed operator's history, or trusting a thief's forged sessions as
human-attested.

**Naming convention.** Nestor calls the identity primitive a *verifier* (its
job is verification). Willow calls the same primitive a *verifier* here, in
this module, so cross-repo readers see the shared vocabulary and the port
stays a port. In willow's user-facing surfaces the same person is often called
the *operator*; the two words name the same primitive from different
directions.

**Legacy fingerprint migration is not this module's job.** Nestor's
``legacy_key`` field holds a shared HMAC secret carried through from
pre-keyring seals. Willow's legacy is a PGP fingerprint held in ``gpg``'s own
keyring — a structurally different animal, and the migration path is
different. The ``legacy_key`` field is preserved here for structural parity
with Nestor's shape; PR3 of the identity-in-session plan lands the actual
PGP-fingerprint bridge.
"""
from __future__ import annotations

import contextlib
import hmac
import json
import os
import pathlib
import secrets
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone


class KeyringError(Exception):
    """The keyring cannot be used as given (unreadable, malformed, unsafe)."""


class UnknownVerifierError(Exception):
    """A keyring is installed and this verifier is not in it.

    Raised at *attestation* time, before anything is written. With per-verifier
    keys there is no key to sign with, and signing with somebody else's — or
    with none — would put a name on an attestation that nothing backs.
    """


class RevokedKeyError(Exception):
    """This verifier's key has been revoked; it cannot make new attestations.

    Whether their *existing* attestations still serve depends on why it was
    revoked — see :meth:`Keyring.revoke`.
    """


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ed25519_generate() -> tuple[bytes, bytes]:
    """(private, public) raw bytes.

    ``cryptography`` is already a willow-mcp dependency, so ed25519 is
    available without an extras marker — differs from Nestor, which puts it
    behind ``[keys]`` to preserve zero-dep default. If cryptography ever
    leaves willow-mcp's dep set, this call will raise ``ImportError`` and
    should be reshaped into an extras marker like Nestor's.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    priv = Ed25519PrivateKey.generate()
    private = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


@dataclass
class VerifierKey:
    """One verifier, one key, and what has happened to it.

    ``kind`` is the key type: ``"hmac"`` (symmetric — ``key`` is the shared
    secret, signing and verifying alike) or ``"ed25519"`` (asymmetric — ``key``
    is the PUBLIC half, and ``private`` holds the private half only on the
    instance where signing happens). An ed25519 entry without ``private`` can
    verify that verifier's attestations but can never produce one — which is
    the property a symmetric key cannot have, and the entire reason the type
    exists (Nestor#17, ported).
    """

    name: str
    key: bytes
    revoked_at: str = ""
    compromised: bool = False
    reason: str = ""
    created_at: str = field(default_factory=_now)
    kind: str = "ed25519"
    private: bytes = field(default=b"", repr=False)

    @property
    def revoked(self) -> bool:
        return bool(self.revoked_at)

    @property
    def can_sign(self) -> bool:
        """A revoked key makes no new attestations, whatever the reason."""
        return not self.revoked

    @property
    def trusted(self) -> bool:
        """Whether attestations already carrying this key's signature still serve.

        True unless the key was reported *compromised* — see the module
        docstring for why that distinction is the operator's to make.
        """
        return not self.compromised

    def to_json(self) -> dict:
        out = {
            "name": self.name,
            "key": self.key.hex(),
            "revoked_at": self.revoked_at,
            "compromised": self.compromised,
            "reason": self.reason,
            "created_at": self.created_at,
            "kind": self.kind,
        }
        if self.private:
            out["private"] = self.private.hex()
        return out

    @classmethod
    def from_json(cls, raw: dict) -> "VerifierKey":
        name = str(raw.get("name", "")).strip()
        if not name:
            raise KeyringError("a keyring entry needs a 'name'")
        try:
            key = bytes.fromhex(str(raw.get("key", "")))
        except ValueError as exc:
            raise KeyringError(
                f"the key for {name!r} is not hex. Keys are stored hex-encoded "
                f"so the file is unambiguous about bytes; generate one with "
                f"`willow-mcp keys add {name}`."
            ) from exc
        if not key:
            raise KeyringError(f"the key for {name!r} is empty")
        kind = str(raw.get("kind", "ed25519")).strip() or "ed25519"
        if kind not in ("hmac", "ed25519"):
            raise KeyringError(
                f"the key for {name!r} has unknown kind {kind!r} "
                f"(one of: hmac, ed25519)"
            )
        try:
            private = bytes.fromhex(str(raw.get("private", "")))
        except ValueError as exc:
            raise KeyringError(f"the private key for {name!r} is not hex") from exc
        if kind == "ed25519" and len(key) != 32:
            raise KeyringError(
                f"the ed25519 public key for {name!r} must be 32 bytes, "
                f"got {len(key)}"
            )
        return cls(
            name=name,
            key=key,
            revoked_at=str(raw.get("revoked_at", "")),
            compromised=bool(raw.get("compromised", False)),
            reason=str(raw.get("reason", "")),
            created_at=str(raw.get("created_at", "")) or _now(),
            kind=kind,
            private=private,
        )


class Keyring:
    """The verifiers this instance can attribute a session to.

    ``legacy_key`` is preserved for structural parity with Nestor's shape.
    Willow's actual legacy migration goes through a PGP fingerprint, not a
    shared HMAC secret; PR3 of the identity-in-session plan lands that bridge
    separately.
    """

    def __init__(
        self,
        verifiers: list[VerifierKey] | None = None,
        legacy_key: bytes | None = None,
        path: str = "",
    ) -> None:
        self._by_name: dict[str, VerifierKey] = {
            v.name: v for v in (verifiers or [])
        }
        self.legacy_key = legacy_key
        self.path = path

    # -- reading ----------------------------------------------------------

    def __contains__(self, name: str) -> bool:
        return name in self._by_name

    def __len__(self) -> int:
        return len(self._by_name)

    def get(self, name: str) -> VerifierKey | None:
        return self._by_name.get(name)

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def entries(self) -> list[VerifierKey]:
        return [self._by_name[n] for n in self.names()]

    def signing_entry(self, name: str) -> VerifierKey:
        """The entry ``name`` signs under, or a refusal saying why they cannot.

        Raises rather than returning ``None``: this is called on the path to
        writing an attestation, and every reason it could fail is a reason not
        to write one. For an ed25519 entry the caller signs with ``.private``
        — and an entry holding only the public half refuses here, because a
        keyring that can verify a peer must not be able to sign as them
        (Nestor#17's acceptance property, enforced at the source).
        """
        entry = self._require_signable(name)
        if entry.kind == "ed25519" and not entry.private:
            raise KeyringError(
                f"{name!r}'s entry holds only the ed25519 PUBLIC key — this "
                f"instance can verify their attestations but can never "
                f"produce one. Signing happens where the private key lives "
                f"(Nestor#17)."
            )
        return entry

    def signing_key(self, name: str) -> bytes:
        """The raw key ``name`` signs with — see :meth:`signing_entry`."""
        entry = self.signing_entry(name)
        return entry.private if entry.kind == "ed25519" else entry.key

    def _require_signable(self, name: str) -> VerifierKey:
        entry = self._by_name.get(name)
        if entry is None:
            raise UnknownVerifierError(
                f"{name or '(empty)'!r} is not in the keyring "
                f"({', '.join(self.names()) or 'no verifiers registered'}). "
                f"An attestation records who was in the seat; with "
                f"per-verifier keys there is no key to sign this one with. "
                f"Add them with `willow-mcp keys add {name or 'NAME'}`, or "
                f"unset WILLOW_KEYRING to go back to the legacy "
                f"PGP-fingerprint path."
            )
        if not entry.can_sign:
            raise RevokedKeyError(
                f"{name!r}'s key was revoked at {entry.revoked_at}"
                f"{' (reported compromised)' if entry.compromised else ''}"
                f"{': ' + entry.reason if entry.reason else ''}. It cannot "
                f"make new attestations. Issue a new key with `willow-mcp "
                f"keys add {name} --rotate`."
            )
        return entry

    def verifying_entry(self, name: str) -> VerifierKey | None:
        """The entry an attestation by ``name`` must verify under, or ``None``
        for "it cannot be trusted at all" — same trust rules as
        :meth:`verifying_key`, with the key type attached.
        """
        entry = self._by_name.get(name)
        if entry is None or not entry.trusted:
            return None
        return entry

    def verifying_key(self, name: str) -> bytes | None:
        """The key an attestation by ``name`` must verify under, or ``None``
        for "it cannot be trusted at all".

        A revoked-but-not-compromised key still verifies its own past
        attestations: rita left, rita's sessions still stand. A compromised
        one verifies nothing, because nothing it signed can be told apart from
        what the thief signed.
        """
        entry = self._by_name.get(name)
        if entry is None or not entry.trusted:
            return None
        return entry.key

    def status(self, name: str) -> str:
        """``"active" | "revoked" | "compromised" | "unknown"`` — for surfaces."""
        entry = self._by_name.get(name)
        if entry is None:
            return "unknown"
        if entry.compromised:
            return "compromised"
        return "revoked" if entry.revoked else "active"

    # -- writing ----------------------------------------------------------

    def add(
        self,
        name: str,
        key: bytes | None = None,
        rotate: bool = False,
        kind: str = "ed25519",
    ) -> VerifierKey:
        """Register ``name`` with ``key`` (a fresh random one by default).

        ``kind="ed25519"`` (the default) with no ``key`` generates a keypair
        here; with ``key`` it registers a peer's PUBLIC key, so this instance
        can verify that peer's attestations without ever being able to produce
        one — verification capability without forgery capability, which is
        what sharing an HMAC could never give (Nestor#17).

        ``kind="hmac"`` is provided for parity with Nestor's shape but is not
        the recommended path for willow: an HMAC keyring puts every operator's
        signing secret on the server, which is exactly the shape this port
        exists to leave behind.

        Replacing an existing entry needs ``rotate=True``. Overwriting a key
        by accident silently invalidates every attestation that verifier ever
        made, which is not something a typo should be able to do.
        """
        name = name.strip()
        if not name:
            raise KeyringError("a verifier needs a name")
        if name in self._by_name and not rotate:
            raise KeyringError(
                f"{name!r} already has a key. Replacing it stops every "
                f"attestation they have already made from verifying — pass "
                f"rotate=True (or `--rotate`) if that is what you mean."
            )
        if kind == "hmac":
            entry = VerifierKey(
                name=name, key=key or secrets.token_bytes(32), kind="hmac"
            )
        elif kind == "ed25519":
            if key is not None:
                # Registering a PEER's public key — the distribution case:
                # this instance can now verify their attestations and nothing
                # more.
                entry = VerifierKey(name=name, key=key, kind="ed25519")
            else:
                private, public = _ed25519_generate()
                entry = VerifierKey(
                    name=name, key=public, kind="ed25519", private=private
                )
        else:
            raise KeyringError(
                f"unknown key kind {kind!r} (one of: hmac, ed25519)"
            )
        self._by_name[name] = entry
        return entry

    def revoke(
        self, name: str, reason: str = "", compromised: bool = False
    ) -> VerifierKey:
        """Retire ``name``'s key. ``compromised`` decides what happens to its
        attestations.

        ``compromised=False`` — the key is being rotated and nobody else ever
        held it. Its past attestations are still that operator's sessions and
        keep serving; it just cannot make new ones.

        ``compromised=True`` — the key was taken. Every attestation it signed
        becomes unservable, because there is no way to tell what was signed
        before the theft from what was signed after. The rows stay on disk and
        surface in the ``sessions_unverifiable`` list (PR4 of the
        identity-in-session plan), which is where a human re-attests them.
        """
        entry = self._by_name.get(name)
        if entry is None:
            raise UnknownVerifierError(f"{name!r} is not in the keyring")
        entry.revoked_at = entry.revoked_at or _now()
        entry.reason = reason or entry.reason
        # One-way: a key reported stolen does not become un-stolen because a
        # later call forgot to say so.
        entry.compromised = entry.compromised or compromised
        return entry

    # -- persistence ------------------------------------------------------

    def to_json(self) -> dict:
        out: dict = {
            "version": 1,
            "verifiers": [e.to_json() for e in self.entries()],
        }
        if self.legacy_key:
            out["legacy_key"] = self.legacy_key.hex()
        return out

    def save(self, path: str | None = None) -> str:
        """Write the keyring, readable by its owner only.

        This file holds every attestation key held on this instance. It is
        written 0600 and :func:`load` refuses one that is readable by anyone
        else, for the same reason ``ssh`` does.
        """
        target = pathlib.Path(path or self.path)
        if not target.name:
            raise KeyringError("no keyring path given")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        # Create with the right mode from the start: a keyring that is briefly
        # world-readable was briefly world-readable.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.to_json(), fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, target)
        self.path = str(target)
        return self.path


def load(path: str) -> Keyring:
    """Read a keyring file. Refuses one other users can read when it holds
    secret material."""
    p = pathlib.Path(path)
    if not p.exists():
        raise KeyringError(
            f"no keyring at {p}. Create one with `willow-mcp keys add NAME`."
        )
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise KeyringError(f"{p} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise KeyringError(f"{p} must contain a JSON object")
    legacy = raw.get("legacy_key") or ""
    try:
        legacy_key = bytes.fromhex(legacy) if legacy else None
    except ValueError as exc:
        raise KeyringError(f"{p}: legacy_key is not hex") from exc
    verifiers = [VerifierKey.from_json(v) for v in raw.get("verifiers", [])]
    # The permission refusal follows the key MATERIAL, not the filename
    # (Nestor#17): a file holding any secret — an hmac key, an ed25519 private
    # half, a legacy key — is refused when other users can read it, exactly as
    # before. A public-only keyring holds nothing forgeable and is deliberately
    # distributable: commit it, mirror it, hand it to the other side of an
    # import.
    holds_secrets = bool(legacy_key) or any(
        v.kind != "ed25519" or v.private for v in verifiers
    )
    mode = os.stat(p).st_mode
    if holds_secrets and mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise KeyringError(
            f"{p} is readable by other users (mode {oct(mode & 0o777)}). It "
            f"holds secret key material — `chmod 600 {p}` and try again. (A "
            f"keyring holding only ed25519 public keys is distributable and "
            f"loads regardless of mode.)"
        )
    return Keyring(verifiers, legacy_key=legacy_key, path=str(p))


# --------------------------------------------------------------------------
# The process-wide keyring
# --------------------------------------------------------------------------

# An explicitly injected keyring, and separately the one read from the
# environment. Keeping them apart is what makes the precedence below
# decidable: with one variable for both, "installed" and "happens to be
# cached" are the same state and the environment can overwrite an injection.
_injected: Keyring | None = None
_from_env: Keyring | None = None
_loaded_from: str | None = None


def set_keyring(k: Keyring | None) -> None:
    """Install the process-wide keyring. **Wins over ``WILLOW_KEYRING``.**

    ``None`` removes the injection, after which the environment is consulted
    again — same precedence Nestor's set_keyring has, and same reason (an
    injection is a caller's explicit statement of intent; the env is a default
    it is overriding).
    """
    global _injected
    _injected = k


def keyring_path() -> str:
    """The path at ``WILLOW_KEYRING``, or ``""`` if unset.

    Env-only, deliberately not routed through a configuration file: this names
    the location of willow's operator trust root. It must be set by the
    environment the human controls, never by a config file that can ride along
    in a cloned working tree and silently redirect the keyring to a planted
    file. Every caller treats ``""`` as "no keyring".
    """
    return os.environ.get("WILLOW_KEYRING", "")


def get_keyring() -> Keyring | None:
    """The installed keyring, the one at ``WILLOW_KEYRING``, or ``None``.

    **An injected keyring wins.** Test suites and the plan's PR1-4 wiring
    install one explicitly; anything with ``WILLOW_KEYRING`` exported in a
    shell should not be able to silently redirect the trust root for a caller
    that said "trust exactly these verifiers." Same reasoning as Nestor's
    ``get_keyring`` docstring.

    The environment's keyring is cached by path — read once, re-read if the
    variable moves. Editing the *file* under a running process is not picked
    up, deliberately: a long-lived MCP server that silently changed who it
    trusts halfway through a shift would be worse than one that needs a
    restart. ``willow-mcp keys`` is a separate short-lived process, and a
    revocation that must take effect now is a restart.
    """
    global _from_env, _loaded_from
    if _injected is not None:
        return _injected
    path = keyring_path()
    if not path:
        return None
    if _from_env is not None and _loaded_from == path:
        return _from_env
    try:
        _from_env = load(path)
    except KeyringError as exc:
        raise KeyringError(
            f"{exc} WILLOW_KEYRING points there — `unset WILLOW_KEYRING` to "
            f"run without per-verifier identity."
        ) from None
    _loaded_from = path
    return _from_env


def preflight() -> Keyring | None:
    """Resolve the keyring now, so a broken configuration refuses at startup.

    Long-lived surfaces (the MCP server itself) call this before they bind
    anything, so ``WILLOW_KEYRING`` pointing at a missing or malformed file
    fails at startup rather than at the first orchestrator write hours in.
    Returns the keyring (or ``None`` if identity is off) and raises
    :class:`KeyringError` if one is configured and unusable.
    """
    return get_keyring()


def enabled() -> bool:
    """Whether per-verifier identity is in force."""
    return get_keyring() is not None


@contextlib.contextmanager
def isolated() -> Iterator[None]:
    """Ignore any ambient ``WILLOW_KEYRING`` (and any injected keyring) for
    the duration of the block, restoring both exactly as found on the way out.

    For a test or an audit probe running in a shell that has
    ``WILLOW_KEYRING`` exported — without this context, the probe's synthetic
    verifier gets refused by the real keyring even though the probe was
    supposed to run against a fixture. Same shape as Nestor's ``isolated()``
    and the same reason (IDEAS §6.98 records the failure mode in Nestor's
    tree).
    """
    global _injected
    had_env = "WILLOW_KEYRING" in os.environ
    saved_env = os.environ.pop("WILLOW_KEYRING", None)
    saved_injected = _injected
    _injected = None
    try:
        yield
    finally:
        _injected = saved_injected
        if had_env:
            os.environ["WILLOW_KEYRING"] = saved_env  # type: ignore[assignment]


def same_key(a: bytes, b: bytes) -> bool:
    """Constant-time equality — for anywhere raw key bytes are compared."""
    return hmac.compare_digest(a, b)
