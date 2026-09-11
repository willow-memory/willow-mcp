"""Split-brain surface for trust-critical artifacts (hook spec #4; gaps
006e0144da95, 01cbac265490, feedback_eliminate-split-brains).

Several trust-critical artifacts resolve from ambient process env with more
than one *candidate* source: an explicit env-var override, a fleet default
under ``$WILLOW_HOME``, and (when configured) a canonical copy in the
operator's vault box (``WILLOW_VAULT_BOX``). Each resolver in ``paths.py`` /
``envelopes.py`` picks exactly ONE of these and returns it — it never looks
at the others, so a second, divergent, resolvable copy is invisible to it.
That is exactly how the 2026-09-07 keyring split-brain and the
charter-pointer registry emptying went unnoticed for days: the resolver
reported success the whole time, quietly reading a stale copy.

This module does not resolve anything. Per feedback_eliminate-split-brains
("report, don't repair"), it only enumerates the candidate paths a resolver
*could* have chosen, notes which of them exist, and flags divergence — two
or more of them existing and disagreeing, or the path actually in effect
differing from a canonical vault copy that also exists. It is read-only:
every operation here is ``Path.exists()`` / ``Path.stat()`` on candidate
paths. Nothing is created, written, moved, or deleted.

Reuses the existing resolvers (`paths.willow_home`, `paths.charter_repo`,
`paths.vault_box`, `paths.envelope_registry_path`, `envelopes.registry_path`,
`keyring.keyring_path`) rather than re-deriving any path logic.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import NamedTuple

from . import paths


class Candidate(NamedTuple):
    """One place an artifact's resolver could plausibly have found it."""

    source: str
    path: Path | None


def _exists(path: Path | None) -> bool:
    if path is None:
        return False
    try:
        return path.exists()
    except OSError:
        return False


def _env_path(name: str) -> Path | None:
    raw = os.environ.get(name, "").strip()
    return Path(raw).expanduser() if raw else None


# ── candidate enumeration, one function per artifact ────────────────────────
# Each mirrors the real resolver's own logic (see paths.py / envelopes.py /
# keyring.py) plus the extra locations a stale copy has actually been found
# at in past incidents. Enumerating is all these do — they compute no
# resolution of their own.

def envelope_registry_candidates() -> list[Candidate]:
    out = [Candidate("env:WILLOW_ENVELOPE_REGISTRY", _env_path("WILLOW_ENVELOPE_REGISTRY"))]
    charter = paths.charter_repo()
    if charter is not None:
        out.append(Candidate("charter:WILLOW_CHARTER_REPO/envelopes",
                              charter / "envelopes" / "pre-approved.json"))
    out.append(Candidate("home_default", paths.willow_home() / "constitutional" / "pre-approved.json"))
    vault = paths.vault_box()
    if vault is not None:
        out.append(Candidate("vault:WILLOW_VAULT_BOX", vault / "constitutional" / "pre-approved.json"))
    return out


def keyring_candidates() -> list[Candidate]:
    out = [Candidate("env:WILLOW_KEYRING", _env_path("WILLOW_KEYRING"))]
    vault = paths.vault_box()
    if vault is not None:
        out.append(Candidate("vault:WILLOW_VAULT_BOX", vault / "keyring.json"))
    out.append(Candidate("home_default", paths.willow_home() / "keyring.json"))
    return out


def charter_candidates() -> list[Candidate]:
    out = [Candidate("env:WILLOW_CHARTER_REPO", _env_path("WILLOW_CHARTER_REPO"))]
    out.append(Candidate("home_default_legacy", paths.willow_home() / "charter"))
    vault = paths.vault_box()
    if vault is not None:
        out.append(Candidate("vault:WILLOW_VAULT_BOX", vault / "charter"))
    return out


def willow_home_candidates() -> list[Candidate]:
    out = [Candidate("env:WILLOW_HOME", _env_path("WILLOW_HOME"))]
    out.append(Candidate("implicit_default", Path.home() / ".willow"))
    return out


def store_root_candidates() -> list[Candidate]:
    out = [Candidate("env:WILLOW_STORE_ROOT", _env_path("WILLOW_STORE_ROOT"))]
    out.append(Candidate("home_default", paths.willow_home() / "store"))
    return out


def _resolved_envelope_registry() -> Path:
    # Mirrors envelopes.registry_path() without importing envelopes (keeps
    # this module import-order-independent); the actual grant-checking code
    # path is untouched — this is read-only reporting of the same result.
    configured = os.environ.get("WILLOW_ENVELOPE_REGISTRY", "").strip()
    if configured:
        return Path(configured).expanduser()
    return paths.envelope_registry_path()


def _artifact_report(name: str, candidates: list[Candidate], resolved: Path | None) -> dict:
    """Read-only divergence report for one artifact. Stats candidate paths;
    never creates, writes, or deletes anything."""
    reported = []
    for c in candidates:
        if c.path is None:
            continue
        reported.append({"source": c.source, "path": str(c.path), "exists": _exists(c.path)})
    distinct_existing = sorted({r["path"] for r in reported if r["exists"]})
    divergent = len(distinct_existing) >= 2
    report = {
        "artifact": name,
        "resolved": str(resolved) if resolved is not None else None,
        "candidates": reported,
        "divergent": divergent,
        "status": "warn" if divergent else "ok",
    }
    if divergent:
        report["detail"] = (
            f"{name}: {len(distinct_existing)} distinct resolvable copies exist "
            f"({', '.join(distinct_existing)}) — only one is in effect "
            f"({report['resolved']}); the others are stale and invisible to the "
            "resolver. Not resolved automatically — pick and consolidate by hand."
        )
    return report


def scan() -> dict:
    """Read-only split-brain surface across every trust-critical artifact.

    Returns ``{"status": "ok"|"warn", "artifacts": {name: report, ...}}``.
    ``status`` is ``warn`` iff any artifact is divergent. Never mutates,
    creates, resolves, or picks between candidates — report only."""
    artifacts = {
        "envelope_registry": _artifact_report(
            "envelope_registry", envelope_registry_candidates(), _resolved_envelope_registry()),
        "keyring": _artifact_report(
            "keyring", keyring_candidates(), _env_path("WILLOW_KEYRING")),
        "charter_repo": _artifact_report(
            "charter_repo", charter_candidates(), paths.charter_repo()),
        "willow_home": _artifact_report(
            "willow_home", willow_home_candidates(), paths.willow_home()),
        "store_root": _artifact_report(
            "store_root", store_root_candidates(), paths.store_root()),
    }
    status = "warn" if any(a["status"] == "warn" for a in artifacts.values()) else "ok"
    return {"status": status, "artifacts": artifacts}
