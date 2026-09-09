"""willow_mcp/remedy.py — the command an operator can actually paste.

Every gate in this codebase that refuses ends by naming the command that would
un-refuse it. For most of this project's life those strings were written as if
the operator's shell were the MCP server's own process. It is not.
``WILLOW_HOME`` and ``WILLOW_KEYRING`` live in the ``env`` block of the stdio
child in ``.mcp.json``, so the server process always has them and a bare
terminal never does.

The printed remedy therefore failed — not occasionally, but every time, at the
start of every session, and it failed in the most expensive way available: the
error it produced named a *different* missing thing than the one the operator
was chasing. ``sign-session`` without ``WILLOW_KEYRING`` reports "the keyring
is not set, use attest-session instead," which sends the reader down the legacy
PGP path when nothing was wrong with the keyring at all.

This module builds those strings from the running process's own resolved
values, so a remedy is copy-pasteable *by construction* rather than by the
author having remembered to say so.

Three rules, all load-bearing:

* **It reads and never writes.** Same contract as ``blockers.py``: a remedy is
  a description of an act, never the act.
* **It never raises.** Every caller is already inside an error path. A second
  exception there replaces a wrong answer with no answer, which is worse.
* **Every value is quoted.** ``keyring.UnknownVerifierError`` used to emit
  ``willow-mcp keys add sean campbell`` for a two-word verifier — argparse
  reads that as the name ``sean`` plus a stray positional. A remedy naming a
  verifier must survive a name with a space in it, because the operator on
  this box has one.
"""
from __future__ import annotations

import os
import shlex

#: Env vars a remedy may need to carry into a bare shell, in the order they
#: are emitted. WILLOW_HOME first: it is the one whose absence is silent
#: rather than loud (a plain terminal resolves the tombstoned ~/.willow and
#: the command *succeeds* against nothing).
_KEYRING_VAR = "WILLOW_KEYRING"
_PGP_VAR = "WILLOW_PGP_FINGERPRINT"


def _resolved_home() -> str:
    """The home this process actually resolved, or "" if it cannot be known.

    Deliberately not ``os.environ["WILLOW_HOME"]``: ``paths.willow_home()``
    applies the retirement guard, so what this prints is the home the server
    is really using rather than the one it was asked for.
    """
    try:
        from . import paths

        return str(paths.willow_home())
    except Exception:
        return ""


def keyring_on() -> bool:
    """Whether this deployment is on the per-verifier keyring path. Never raises.

    ``keyring.enabled()`` RAISES ``KeyringError`` when ``WILLOW_KEYRING`` names
    a file that is not there. That is not a hypothetical: inside the Kart
    sandbox the variable crosses the boundary (``env_prefixes`` carries
    ``WILLOW_``) and the file does not (gap ``4e1825878677``), so every caller
    that asks "is the keyring on?" in a sandbox gets an exception rather than
    an answer. A read-only reporter and a remedy builder must not inherit that.

    A keyring that is configured but unloadable still answers True: the
    deployment is on the keyring path and the remedy is to fix that keyring,
    not to send the operator down the legacy PGP branch.
    """
    try:
        from . import keyring as keyring_mod

        return keyring_mod.enabled()
    except Exception:
        return bool(os.environ.get(_KEYRING_VAR, "").strip())


def _assignment(name: str, value: str) -> str:
    value = (value or "").strip()
    return f"{name}={shlex.quote(value)}" if value else ""


def env_prefix(*, keyring: bool = False, pgp: bool = False) -> str:
    """``VAR=value VAR=value `` for the vars this remedy needs, or "".

    Only emits a var that is actually set in this process — printing
    ``WILLOW_KEYRING=`` when there is no keyring would be a new lie in place
    of the old one. Trailing space included when non-empty so callers can
    concatenate without deciding.
    """
    parts = [_assignment("WILLOW_HOME", _resolved_home())]
    if keyring:
        parts.append(_assignment(_KEYRING_VAR, os.environ.get(_KEYRING_VAR, "")))
    if pgp:
        parts.append(_assignment(_PGP_VAR, os.environ.get(_PGP_VAR, "")))
    prefix = " ".join(p for p in parts if p)
    return f"{prefix} " if prefix else ""


def sign_session(session_id: str, verifier: str = "NAME") -> str:
    """The keyring (v2) attestation command, runnable in a bare shell.

    ``verifier`` defaults to the literal placeholder ``NAME`` — ``shlex.quote``
    leaves that bare, so the placeholder still reads as a placeholder, while a
    real name with a space in it comes back quoted.
    """
    return (
        f"{env_prefix(keyring=True)}willow-mcp sign-session "
        f"{shlex.quote(session_id)} --verifier {shlex.quote(verifier)}"
    )


def attest_session(session_id: str) -> str:
    """The legacy PGP (v1) attestation command, runnable in a bare shell."""
    return (
        f"{env_prefix(pgp=True)}willow-mcp attest-session "
        f"{shlex.quote(session_id)}"
    )


def keys_add(name: str) -> str:
    """The command that adds ``name`` to the keyring, with the name quoted."""
    return f"{env_prefix(keyring=True)}willow-mcp keys add {shlex.quote(name or 'NAME')}"


def attestation_command(session_id: str, *, keyring_on: bool, verifier: str = "NAME") -> str:
    """Whichever of the two attestation paths this deployment is actually on.

    Callers that branch on ``keyring_mod.enabled()`` to pick a remedy string
    should call this instead, so the branch exists once.
    """
    if keyring_on:
        return sign_session(session_id, verifier)
    return attest_session(session_id)
