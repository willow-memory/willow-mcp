"""willow_mcp/env_fingerprint.py — a fingerprint of the broker's env file,
never its values.

Follow-on to decision ``1bd6fd29`` (2026-09-22, "operations are Willow's…
the operator's only keyboard act is the seal") on the shape sealed
``e961aff8`` (:mod:`reloader`): today the reloader restarts the broker onto
a sealed ``git_pull`` receipt only. A change to ``$WILLOW_HOME/env`` — a
rotated provider key, ``WILLOW_PGP_FINGERPRINT`` after the trust-owner key
is generated, ``WILLOW_MCP_APPS_ROOT`` added — has no receipt, so the
broker keeps running on stale env until someone types ``systemctl --user
restart`` by hand. That keyboard act is what this module (paired with
:mod:`reloader`'s env-trigger functions) removes.

Env values are secrets. They can never ride in a pair, a receipt, or the
journal, so a change has to be *detected*, never *declared*: this module
never writes a raw env value anywhere. What it writes are:

* a SHA-256 **digest** over the sorted ``name=value`` lines of the file
  (one hash for the whole file — this is what a FRANK receipt's
  ``fingerprint_before``/``fingerprint_after`` carry), and
* a per-key SHA-256 **digest of each value** (never the value itself),
  kept only in the broker's own startup-state file so a later tick can
  tell an added/removed key from a changed one by NAME, without ever
  reading two copies of the file across process boundaries. A digest is
  irreversible; nothing here is a value, however this dict is serialized,
  logged, or grepped.

Three states, never collapsed (INVARIANTS §1), used in two different
places for two different questions:

* :func:`read_state` answers "what did the RUNNING broker load": ``empty``
  (no state file — an older broker that predates this module, or one that
  has not started since it landed; say so, do nothing), ``unreachable``
  (the file is there but unreadable — corrupt JSON, a permission problem),
  ``populated`` (a fingerprint is on record).
* :func:`compute_fingerprint` answers "what does the file on disk hold
  RIGHT NOW": ``empty`` (no such file), ``unreachable`` (exists but
  unreadable), ``populated`` (a fingerprint was computed).

The broker's own write is not a request (reloader.py §6): the env file is
owned by the broker's uid, so the broker changing its own env and having
the reloader restart it would be the self-grant one process removed. This
module only detects; :mod:`reloader` is what turns a detected diff into a
FRANK request, and only a sealed Nestor decision turns that request into
the one act.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import paths

_SYSTEMCTL_TIMEOUT_S = 15


# ── locations ─────────────────────────────────────────────────────────────────

def state_dir() -> Path:
    return paths.willow_home() / "serve"


def state_path() -> Path:
    """Where the broker records the env fingerprint it loaded at startup —
    a sibling of where serve mode would keep other startup state, had one
    already existed (none did: `heartbeat.py` is per-worker, not per-broker).
    0600 — this file holds per-key value digests, and a digest of a secret
    is still worth keeping off a shared mode."""
    return state_dir() / "env_fingerprint.json"


def default_env_path() -> Path:
    return paths.willow_home() / "env"


# ── the fingerprint ──────────────────────────────────────────────────────────

def _parse_env_lines(text: str) -> list[tuple[str, str]]:
    """Parse ``NAME=VALUE`` lines the way a systemd ``EnvironmentFile=``
    does: blank lines and ``#``-comments are skipped, everything else kept
    verbatim — the fingerprint hashes what systemd would actually load, not
    a reinterpretation of it (no quote stripping, no export prefix)."""
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        name = name.strip()
        if name:
            out.append((name, value))
    return out


def compute_fingerprint(path: Path) -> dict:
    """The three-state read of one env file.

    ``{"state": "empty"}`` — no such file.
    ``{"state": "unreachable", "cause": ...}`` — exists but could not be read.
    ``{"state": "populated", "keys": [sorted names], "digest": sha256hex,
    "key_digests": {name: sha256hex(value)}}`` on success. ``digest`` is
    the single hash over every sorted ``name=value`` line — what a FRANK
    receipt carries. ``key_digests`` never leaves this process except into
    the 0600 state file: it exists only so two fingerprints computed in
    different ticks (different processes, even) can be diffed key-by-key
    without either one holding the other's raw values.
    """
    try:
        if not path.is_file():
            return {"state": "empty"}
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}"}
    pairs = sorted(_parse_env_lines(text), key=lambda kv: kv[0])
    keys = [k for k, _ in pairs]
    whole = hashlib.sha256()
    key_digests: dict[str, str] = {}
    for k, v in pairs:
        whole.update(k.encode("utf-8"))
        whole.update(b"=")
        whole.update(v.encode("utf-8"))
        whole.update(b"\n")
        key_digests[k] = hashlib.sha256(v.encode("utf-8")).hexdigest()
    return {"state": "populated", "keys": keys, "digest": whole.hexdigest(),
            "key_digests": key_digests}


def summary(fp: dict) -> str:
    """A one-line stand-in for a fingerprint in a refusal reason or a
    receipt field — the digest when populated, else the bare state."""
    if fp.get("state") == "populated":
        return fp.get("digest", "")
    return f"<{fp.get('state', 'unknown')}>"


def diff_keys(before: dict, after: dict) -> dict:
    """``{"keys_added", "keys_removed", "keys_changed"}`` — NAMES only,
    never a value or a value's digest. Both ``before``/``after`` are
    ``populated`` :func:`compute_fingerprint` results (or the equivalent
    read back from :func:`read_state`); a key absent from one side's
    ``key_digests`` is treated as absent from that side entirely, so this
    degrades gracefully against an older state-file shape that predates
    ``key_digests``."""
    b = before.get("key_digests") or {}
    a = after.get("key_digests") or {}
    bset, aset = set(b), set(a)
    return {
        "keys_added": sorted(aset - bset),
        "keys_removed": sorted(bset - aset),
        "keys_changed": sorted(k for k in (bset & aset) if b[k] != a[k]),
    }


def fingerprints_equal(a: dict, b: dict) -> bool:
    """Same state, and — when both are populated — the same digest. Two
    ``empty``s or two ``unreachable``s of different ``cause`` still count
    as equal: the cause is diagnostic text, not part of the fingerprint."""
    if a.get("state") != b.get("state"):
        return False
    if a.get("state") != "populated":
        return True
    return a.get("digest") == b.get("digest")


# ── resolving which file the broker's unit actually loads ─────────────────────

def resolve_env_file(unit: str, *, runner: Optional[Callable] = None) -> Path:
    """``EnvironmentFile=`` of ``unit`` per ``systemctl --user show``, or
    ``$WILLOW_HOME/env`` when that cannot be read — no live unit to ask
    (stdio, or a box with no user bus reachable from here), or the unit
    carries no ``EnvironmentFile=`` at all. Never raises."""
    run = runner or subprocess.run
    try:
        proc = run(
            ["systemctl", "--user", "show", unit, "--property=EnvironmentFiles"],
            capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return default_env_path()
    if proc.returncode != 0:
        return default_env_path()
    out = (proc.stdout or "").strip()
    prefix = "EnvironmentFiles="
    if not out.startswith(prefix):
        return default_env_path()
    value = out[len(prefix):].strip()
    if not value:
        return default_env_path()
    # systemd prints e.g. "/home/x/.willow/env (ignore_errors=no)"; the path
    # is the first whitespace-delimited token.
    first = value.split()[0]
    return Path(first) if first else default_env_path()


# ── the running broker's own record ────────────────────────────────────────────

def read_state() -> dict:
    """What the RUNNING broker loaded, per its own startup record.

    ``{"state": "empty"}`` — no state file: an older broker that predates
    this module, or one that has not (re)started since it landed. Nothing
    to compare against, so the caller does nothing rather than guess.
    ``{"state": "unreachable", "cause": ...}`` — the file exists but could
    not be parsed.
    ``{"state": "populated", "env_fingerprint": {...}, "env_loaded_at": ...}``.
    """
    p = state_path()
    try:
        if not p.is_file():
            return {"state": "empty"}
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}"}
    if not isinstance(data, dict) or not isinstance(data.get("env_fingerprint"), dict):
        return {"state": "unreachable", "cause": "malformed env-fingerprint state file"}
    return {"state": "populated", "env_fingerprint": data["env_fingerprint"],
            "env_loaded_at": data.get("env_loaded_at")}


def record_startup(env_path: Optional[Path] = None) -> dict:
    """Called once at broker startup (serve mode): fingerprint the env file
    this process loaded and record it as "what's running" — the baseline
    :func:`reloader.check_env` compares the live file against on every
    tick. Never raises: a failure to write telemetry must not block
    startup, so it is reported in the return value and swallowed.

    ``env_path`` defaults to ``$WILLOW_HOME/env`` — the broker's own
    process does not go through :func:`resolve_env_file` (that call needs
    a live user-bus round trip the broker itself has no reason to make of
    itself; it just knows the file it read to build its own environment)."""
    path = Path(env_path) if env_path is not None else default_env_path()
    fp = compute_fingerprint(path)
    record = {
        "env_fingerprint": fp,
        "env_loaded_at": datetime.now(timezone.utc).isoformat(),
        "env_path": str(path),
    }
    p = state_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except OSError as exc:
        record["write_error"] = f"{type(exc).__name__}: {exc}"
    return record
