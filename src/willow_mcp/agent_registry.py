"""agent_registry — the operator-side keystore binding an agent identity to a
shared HMAC secret and a trust ceiling (willow-gate seam, decision D2).

Layout (outside mcp_apps/ so no store/list tool can enumerate it; the whole
`gate/` dir is 0700 and on the PreToolUse guard's owned side — a keystore,
guarded like one):

    $WILLOW_HOME/gate/registry.json          {agent_id: {"max_trust": int}}
    $WILLOW_HOME/gate/secrets/<agent_id>.key  32 random bytes, 0600, atomic

The ceiling registry stays readable/auditable; secret material sits in per-agent
0600 files. This is CLI/operator-only — no MCP tool may register, rotate, read, or
revoke a secret (the sudo invariant: an agent may request standing, never mint
it). See docs/design/willow-gate-seam.md §D2.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets as _secrets
import threading
from pathlib import Path
from typing import Optional

from . import paths

logger = logging.getLogger(__name__)

_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
_SECRET_MIN_BYTES = 32


def _gate_dir() -> Path:
    d = paths.gate_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError as e:
        # A keystore dir we could not lock down to 0700 is a hardening failure —
        # surface it loudly rather than silently trusting a possibly-0755 dir.
        logger.warning("agent_registry: could not chmod 0700 %s: %s", d, e)
    return d


def _registry_path() -> Path:
    return _gate_dir() / "registry.json"


def _secrets_dir() -> Path:
    d = _gate_dir() / "secrets"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError as e:
        logger.warning("agent_registry: could not chmod 0700 %s: %s", d, e)
    return d


def _tmp_suffix() -> str:
    # pid + thread id + random token: two threads (or interpreters) writing the
    # same agent's key/registry cannot share a temp path and publish a torn file.
    return f".tmp-{os.getpid()}-{threading.get_ident()}-{_secrets.token_hex(4)}"


def _validate_id(agent_id: str) -> str:
    if not agent_id or not _ID_RE.match(agent_id):
        raise ValueError(f"invalid agent_id: {agent_id!r}")
    return agent_id


def _read_registry() -> dict:
    p = _registry_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_registry(reg: dict) -> None:
    p = _registry_path()
    tmp = p.with_suffix(_tmp_suffix())
    tmp.write_text(json.dumps(reg, indent=2, sort_keys=True))
    os.replace(tmp, p)


def register_agent(agent_id: str, max_trust: int, secret: Optional[bytes] = None) -> dict:
    """Bind `agent_id` to a 32-byte secret and a MAX trust ceiling (0..4).
    Operator/CLI-only. Returns the secret hex ONCE so the operator can install it
    into the agent's client-side signer (the same secret verifies here and signs
    there — symmetric, per D2). Re-registering rotates the secret."""
    _validate_id(agent_id)
    if not isinstance(max_trust, int) or not 0 <= max_trust <= 4:
        raise ValueError("max_trust must be an int in 0..4")
    secret = secret if secret is not None else _secrets.token_bytes(_SECRET_MIN_BYTES)
    if len(secret) < _SECRET_MIN_BYTES:
        raise ValueError(f"secret must be >= {_SECRET_MIN_BYTES} bytes")
    key_path = _secrets_dir() / f"{agent_id}.key"
    tmp = key_path.with_suffix(_tmp_suffix())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, secret)
    finally:
        os.close(fd)
    os.replace(tmp, key_path)
    reg = _read_registry()
    reg[agent_id] = {"max_trust": max_trust}
    _write_registry(reg)
    return {"agent_id": agent_id, "max_trust": max_trust, "secret_hex": secret.hex()}


def is_registered(agent_id: str) -> bool:
    """True if a registry ENTRY exists for this agent, regardless of whether its
    secret file is currently readable. The enforcement gate needs this distinct
    from load(): a registered agent whose secret is momentarily unreadable must
    fail CLOSED (deny), not be mistaken for an unregistered one and waved through
    on manifest-only auth."""
    try:
        _validate_id(agent_id)
    except ValueError:
        return False
    rec = _read_registry().get(agent_id)
    return isinstance(rec, dict) and "max_trust" in rec


def load(agent_id: str) -> Optional[tuple[bytes, int]]:
    """(secret, max_trust) for a registered agent whose secret is present, readable,
    and long enough, else None. The one reader the binder uses; never exposed
    through an MCP tool. Callers that must distinguish "not registered" from
    "registered but secret unusable" pair this with is_registered() and fail
    closed on the latter."""
    try:
        _validate_id(agent_id)
    except ValueError:
        return None
    reg = _read_registry()
    rec = reg.get(agent_id)
    if not isinstance(rec, dict) or "max_trust" not in rec:
        return None
    key_path = _secrets_dir() / f"{agent_id}.key"
    try:
        secret = key_path.read_bytes()
    except OSError as e:
        logger.warning("agent_registry: secret for %r unreadable: %s", agent_id, e)
        return None
    # A short/corrupt key (torn write, truncation, tampering within 0600) would
    # collapse the HMAC keyspace — reject it on read, not only on register.
    if len(secret) < _SECRET_MIN_BYTES:
        logger.warning("agent_registry: secret for %r is too short (%d bytes) — rejecting",
                       agent_id, len(secret))
        return None
    return secret, int(rec["max_trust"])


def list_agents() -> dict:
    """{agent_id: max_trust} — auditable, no secret material."""
    return {a: r.get("max_trust") for a, r in _read_registry().items() if isinstance(r, dict)}


def revoke(agent_id: str) -> bool:
    """Remove an agent's secret + registry entry. Operator/CLI-only."""
    _validate_id(agent_id)
    reg = _read_registry()
    had = agent_id in reg
    reg.pop(agent_id, None)
    _write_registry(reg)
    try:
        (_secrets_dir() / f"{agent_id}.key").unlink()
    except OSError:
        pass
    return had
