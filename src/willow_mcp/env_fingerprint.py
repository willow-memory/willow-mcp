"""willow_mcp/env_fingerprint.py — a fingerprint of the broker's env, never
its values, read the way the unit actually carries it.

Follow-on to decision ``1bd6fd29`` (2026-09-22, "operations are Willow's…
the operator's only keyboard act is the seal") on the shape sealed
``e961aff8`` (:mod:`reloader`): today the reloader restarts the broker onto
a sealed ``git_pull`` receipt only. A change to the broker's env — a
rotated provider key, ``WILLOW_PGP_FINGERPRINT`` after the trust-owner key
is generated, ``WILLOW_MCP_APPS_ROOT`` added — has no receipt, so the
broker keeps running on stale env until someone types ``systemctl --user
restart`` by hand. That keyboard act is what this module (paired with
:mod:`reloader`'s env-trigger functions) removes.

Rework (Loki audit E79FCAE7, findings F2/F3):

**F2 — no per-key oracle.** The first cut of this module kept a per-key
SHA-256 digest of each VALUE (``key_digests``) so a later tick could tell
an added/removed key from a changed one by name. That digest is exactly
the oracle the brief forbade: an unsalted hash of a short secret is a
rainbow-table lookup, and it went into a 0600 file on the same box as
everything else. It is gone. This module now keeps and writes exactly what
the brief asked for — ONE digest over the whole sorted ``name=value`` set,
key NAMES beside it, nothing keyed per value. The unavoidable cost: two
fingerprints with the same key NAMES but a different overall digest cannot
say WHICH name's value moved — see :func:`diff_keys`, which reports every
name common to both sides as "changed" in that case rather than guessing,
because guessing would mean deriving something from the values themselves.

**F3 — read the unit the way the box actually has it.** The live
``willow-mcp-serve.service`` and its drop-ins on this fleet carry no
``EnvironmentFile=`` at all — env arrives as ``Environment=`` lines. The
first cut always fell back to fingerprinting ``$WILLOW_HOME/env``, a file
that unit never loads, and called the result "the unit's env." Read the
same systemd output the box actually has (``EnvironmentFiles=`` when the
unit does have one, ``Environment=`` lines otherwise, a real fallback file
path only as a last resort when neither systemctl call nor the unit itself
gives an answer) — see :func:`resolve_env_source`. Every fingerprint now
carries ``env_source`` (``environment_file`` | ``unit_environment`` |
``fallback``) so a mismatch is legible rather than silently comparing two
different things.

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
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import paths

_SYSTEMCTL_TIMEOUT_S = 15

#: Mirrors reloader.DEFAULT_UNIT/reloader._ENV_UNIT without importing
#: reloader (which imports this module) — a plain constant, not policy.
DEFAULT_UNIT = "willow-mcp-serve.service"
_ENV_UNIT_VAR = "WILLOW_RELOADER_UNIT"


def _default_unit() -> str:
    return os.environ.get(_ENV_UNIT_VAR, DEFAULT_UNIT).strip() or DEFAULT_UNIT


# ── locations ─────────────────────────────────────────────────────────────────

def state_dir() -> Path:
    return paths.willow_home() / "serve"


def state_path() -> Path:
    """Where the broker records the env fingerprint it loaded at startup —
    a sibling of where serve mode would keep other startup state, had one
    already existed (none did: `heartbeat.py` is per-worker, not per-broker).
    0600 — belt and suspenders; this file holds only names and one digest,
    never a value or anything keyed per value, but it is still not a file
    that needs to be world-readable."""
    return state_dir() / "env_fingerprint.json"


def default_env_path() -> Path:
    """The last-resort fallback ONLY — used when systemctl cannot be asked
    at all (missing, timeout, unit unknown) or answers with neither
    ``EnvironmentFile=`` nor ``Environment=``. Never assumed to be what a
    live unit actually loads; see :func:`resolve_env_source`."""
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


def _fingerprint_pairs(pairs: list[tuple[str, str]]) -> dict:
    """The one shape every source (file or ``Environment=`` lines) reduces
    to: sorted key NAMES and ONE SHA-256 digest over the whole sorted
    ``name=value`` set. Nothing per key — see the module docstring, F2."""
    ordered = sorted(pairs, key=lambda kv: kv[0])
    keys = [k for k, _ in ordered]
    whole = hashlib.sha256()
    for k, v in ordered:
        whole.update(k.encode("utf-8"))
        whole.update(b"=")
        whole.update(v.encode("utf-8"))
        whole.update(b"\n")
    return {"state": "populated", "keys": keys, "digest": whole.hexdigest()}


def compute_fingerprint(path: Path) -> dict:
    """The three-state read of one env FILE.

    ``{"state": "empty"}`` — no such file.
    ``{"state": "unreachable", "cause": ...}`` — exists but could not be read.
    ``{"state": "populated", "keys": [sorted names], "digest": sha256hex}``
    on success — the single hash over every sorted ``name=value`` line, and
    nothing else; no per-key material of any kind survives this call.
    """
    try:
        if not path.is_file():
            return {"state": "empty"}
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}"}
    return _fingerprint_pairs(_parse_env_lines(text))


def compute_fingerprint_from_pairs(pairs: list[tuple[str, str]]) -> dict:
    """Same shape as :func:`compute_fingerprint`, for a unit's
    ``Environment=`` lines (already parsed into ``(name, value)`` pairs) —
    there is no file to report ``empty``/``unreachable`` for; an empty list
    of pairs is simply a populated fingerprint of nothing."""
    return _fingerprint_pairs(list(pairs))


def summary(fp: dict) -> str:
    """A one-line stand-in for a fingerprint in a refusal reason or a
    receipt field — the digest when populated, else the bare state."""
    if fp.get("state") == "populated":
        return fp.get("digest", "")
    return f"<{fp.get('state', 'unknown')}>"


def diff_keys(before: dict, after: dict) -> dict:
    """``{"keys_added", "keys_removed", "keys_changed"}`` — NAMES only,
    never a value, never anything derived per-key from a value (F2: there
    is no per-key digest left to consult).

    Rework (Loki 747B0C04, R3): the first cut reported every name common to
    both sides as ``keys_changed`` whenever the digest differed — SAFE (no
    oracle) but FALSE for all but at most one of them: a rotated single key
    among twenty unrelated ones told the desk twenty names "changed." A
    single aggregate digest genuinely cannot say WHICH common name moved,
    so this stops claiming it can. ``keys_added``/``keys_removed`` remain
    exact (straight name-set differences). In place of ``keys_changed``,
    ``values_changed`` is ONE boolean — true when the two fingerprints
    differ at all (added, removed, or a same-name-set value edit) — naming
    no key, over- or under-claiming nothing about any specific name. Loki
    explicitly ruled out a keyed/salted per-key digest as a fix: the key
    would have to live on the same disk, same uid, as the baseline the
    broker writes and the reloader reads, so anyone holding both holds the
    oracle again. No per-key claim survives here in any form.
    """
    bkeys = set(before.get("keys") or [])
    akeys = set(after.get("keys") or [])
    added = sorted(akeys - bkeys)
    removed = sorted(bkeys - akeys)
    same_digest = before.get("digest") == after.get("digest") and before.get("state") == after.get("state")
    return {"keys_added": added, "keys_removed": removed, "values_changed": not same_digest}


def fingerprints_equal(a: dict, b: dict) -> bool:
    """Same state, and — when both are populated — the same digest. Two
    ``empty``s or two ``unreachable``s of different ``cause`` still count
    as equal: the cause is diagnostic text, not part of the fingerprint."""
    if a.get("state") != b.get("state"):
        return False
    if a.get("state") != "populated":
        return True
    return a.get("digest") == b.get("digest")


# ── resolving what the unit actually loads (F3) ────────────────────────────────

def _parse_show_props(stdout: str) -> dict:
    out: dict[str, str] = {}
    for line in (stdout or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k] = v
    return out


def _parse_environment_pairs(raw: str) -> list[tuple[str, str]]:
    """systemd's ``Environment=`` show output: space-separated
    ``NAME=VALUE`` tokens, shell-quoted the way systemd escapes them.
    ``shlex`` handles the common cases (quoted values containing spaces);
    this is a best-effort parse of systemd's own escaping grammar, which is
    not a strict shell grammar, but is close enough for the values this
    fleet actually sets. A token that fails to split cleanly is skipped
    rather than guessed at."""
    try:
        tokens = shlex.split(raw or "")
    except ValueError:
        tokens = (raw or "").split()
    out: list[tuple[str, str]] = []
    for tok in tokens:
        if "=" in tok:
            name, _, value = tok.partition("=")
            if name:
                out.append((name, value))
    return out


def resolve_env_source(unit: str, *, runner: Optional[Callable] = None) -> dict:
    """Where THIS unit's env actually comes from, read the way
    ``systemctl --user show`` reports it — never assumed. Three shapes:

    ``{"source": "environment_file", "path": Path}`` — the unit carries an
    ``EnvironmentFile=``; fingerprint that file.

    ``{"source": "unit_environment", "pairs": [(name, value), ...]}`` — no
    ``EnvironmentFile=``, but ``Environment=`` lines are present (the shape
    this fleet's live ``willow-mcp-serve.service`` and its drop-ins
    actually use); fingerprint THOSE pairs directly, never a file.

    ``{"source": "fallback", "path": $WILLOW_HOME/env}`` — systemctl is
    unreachable/missing/times out, or the unit carries neither — the only
    case where a guessed file path is used, and it is always labeled as
    exactly that: a guess, not a read of the unit.

    Never raises.
    """
    run = runner or subprocess.run
    try:
        proc = run(
            ["systemctl", "--user", "show", unit, "--property=EnvironmentFiles,Environment"],
            capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"source": "fallback", "path": default_env_path()}
    if proc.returncode != 0:
        return {"source": "fallback", "path": default_env_path()}
    props = _parse_show_props(proc.stdout)
    env_files = (props.get("EnvironmentFiles") or "").strip()
    if env_files:
        first = env_files.split()[0]
        if first:
            return {"source": "environment_file", "path": Path(first)}
    environment = (props.get("Environment") or "").strip()
    if environment:
        pairs = _parse_environment_pairs(environment)
        if pairs:
            return {"source": "unit_environment", "pairs": pairs}
    return {"source": "fallback", "path": default_env_path()}


def fingerprint_source(src: dict) -> dict:
    """The ``{state, keys, digest}`` fingerprint of a
    :func:`resolve_env_source` result, plus ``env_source``/``env_ref`` so a
    caller (a receipt, the state file) can always say WHERE this reading
    came from — ``env_ref`` is the file path for ``environment_file``/
    ``fallback`` sources, ``None`` for ``unit_environment`` (there is no
    single file to name)."""
    if src.get("source") == "unit_environment":
        fp = compute_fingerprint_from_pairs(src.get("pairs") or [])
        ref = None
    else:
        path = src.get("path") or default_env_path()
        fp = compute_fingerprint(path)
        ref = str(path)
    return {**fp, "env_source": src.get("source", "fallback"), "env_ref": ref}


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


def record_startup(*, unit: Optional[str] = None, runner: Optional[Callable] = None,
                    source: Optional[dict] = None) -> dict:
    """Called once at broker startup (serve mode): fingerprint the env this
    process loaded and record it as "what's running" — the baseline
    :func:`reloader.check_env` compares the live read against on every
    tick. Never raises: a failure to write telemetry must not block
    startup, so it is reported in the return value and swallowed.

    Resolves via the SAME :func:`resolve_env_source` the detect side uses
    (F3) — not ``os.environ``, even though this process could read its own
    environment directly, because ``os.environ`` also carries everything
    systemd/the shell inherited (``PATH``, ``HOME``, ...) that
    ``resolve_env_source`` never claims to fingerprint; comparing the two
    would manufacture a permanent false diff. ``source`` lets a caller
    (tests, or a future caller that already resolved it) skip the
    systemctl round trip; production boot leaves it unset.
    """
    src = source if source is not None else resolve_env_source(unit or _default_unit(), runner=runner)
    fp = fingerprint_source(src)
    record = {
        "env_fingerprint": fp,
        "env_loaded_at": datetime.now(timezone.utc).isoformat(),
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
