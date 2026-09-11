"""Split-brain surface for trust-critical artifacts (hook spec #4; gaps
006e0144da95, 01cbac265490, feedback_eliminate-split-brains).

Several trust-critical artifacts resolve from ambient process env with more
than one *candidate* source: an explicit env-var override, a fleet default
under ``$WILLOW_HOME``, and (when configured) a canonical copy in the
operator's vault box (``WILLOW_VAULT_BOX``). Each resolver in ``paths.py`` /
``envelopes.py`` / ``keyring.py`` picks exactly ONE of these and returns it —
it never looks at the others. When a leftover copy sits at a location the
resolver would never look at (a lower-precedence path shadowed by one that is
set, or a fallback the real resolver has no code path to reach at all), the
leftover is inert: nobody reads it, and reporting it as "divergent" is a
false alarm, not a hazard. The 2026-09-07 keyring split-brain and the
charter-pointer registry emptying were different — those were leftover
copies at locations a resolver genuinely *could* still land on depending on
env, so a resolver could quietly end up on the wrong one of two paths that
were both really in play.

This module does not resolve anything. Per feedback_eliminate-split-brains
("report, don't repair"), it enumerates only the candidate paths a resolver
could *actually* land on given the current environment, notes which of them
exist, and flags divergence — two or more of those actually-reachable
candidates existing and disagreeing. It is read-only: every operation here is
``Path.exists()`` / ``Path.stat()`` on candidate paths. Nothing is created,
written, moved, or deleted.

Candidate enumeration is written to mirror each real resolver's own
precedence exactly (``paths.willow_home``, ``paths.charter_repo``,
``keyring.keyring_path``, ``envelopes.registry_path`` /
``paths.envelope_registry_path``) rather than paraphrasing it from memory —
that mirroring is what keeps this module from drifting out of sync with the
resolvers it reports on:

* ``keyring.keyring_path()`` is env-only (``WILLOW_KEYRING``) with no
  fallback of any kind — a leftover ``keyring.json`` in the vault box or
  under ``$WILLOW_HOME`` is never consulted by anything, whatever else is
  set, so it is not a candidate here either.
* ``paths.charter_repo()`` is env-only (``WILLOW_CHARTER_REPO``) with no
  fallback — same reasoning, and when it is unset there is no charter
  authority in effect at all, so nothing can be "divergent" against it.
* ``paths.willow_home()`` really does fall back to ``~/.willow``, but only
  when ``WILLOW_HOME`` is unset. When it is set, ``~/.willow`` merely
  existing (as it does on a box that migrated its home) is never reached by
  any resolver and is not counted.
* ``envelope_registry`` genuinely can have two live candidates at once: the
  ``WILLOW_ENVELOPE_REGISTRY`` override (honoured by ``envelopes.registry_path``,
  the grant-matching authority) and the charter-or-home default (honoured by
  ``paths.envelope_registry_path``, which ``home_init`` seeds independently of
  the override). Both are real, currently-executing code paths, so both are
  reachable candidates regardless of which one wins for grant matching.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import NamedTuple

from . import paths


class Candidate(NamedTuple):
    """One place an artifact's resolver could plausibly have found it.

    ``reachable`` is whether a real resolver, given the *current* environment,
    could actually land on this path — as opposed to a lower-precedence path
    that is shadowed outright by something higher already being set. A
    candidate that exists but is not reachable is a leftover, not a split
    brain: nothing in the codebase will ever read it under this environment.
    """

    source: str
    path: Path | None
    reachable: bool = True


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
# Each enumerates only the paths a real resolver could actually land on given
# the current environment. Enumerating and marking reachability is all these
# do — they compute no resolution of their own.

def envelope_registry_candidates() -> list[Candidate]:
    out = [Candidate("env:WILLOW_ENVELOPE_REGISTRY", _env_path("WILLOW_ENVELOPE_REGISTRY"))]
    # paths.envelope_registry_path() (used directly by home_init to seed the
    # registry) is a real, always-executing code path that never consults
    # WILLOW_ENVELOPE_REGISTRY — so its own answer (charter-or-home) is a
    # genuinely reachable candidate whether or not the override is set.
    charter = paths.charter_repo()
    if charter is not None:
        out.append(Candidate("charter:WILLOW_CHARTER_REPO/envelopes",
                              charter / "envelopes" / "pre-approved.json"))
    else:
        out.append(Candidate("home_default", paths.willow_home() / "constitutional" / "pre-approved.json"))
    return out


def keyring_candidates() -> list[Candidate]:
    # keyring.keyring_path() is WILLOW_KEYRING-or-nothing — no vault or home
    # fallback exists in the real resolver, so none is enumerated here either.
    return [Candidate("env:WILLOW_KEYRING", _env_path("WILLOW_KEYRING"))]


def charter_candidates() -> list[Candidate]:
    # paths.charter_repo() is WILLOW_CHARTER_REPO-or-None — no fallback.
    # Leftover directories at $WILLOW_HOME/charter or the vault box are never
    # consulted by anything, whether or not the env var is set.
    return [Candidate("env:WILLOW_CHARTER_REPO", _env_path("WILLOW_CHARTER_REPO"))]


def willow_home_candidates() -> list[Candidate]:
    env_path = _env_path("WILLOW_HOME")
    out = [Candidate("env:WILLOW_HOME", env_path)]
    # The implicit default is only ever reached by paths.willow_home() when
    # WILLOW_HOME is unset. When it is set, ~/.willow merely existing (e.g. a
    # box that migrated homes) is shadowed outright — nothing reads it.
    out.append(Candidate("implicit_default", Path.home() / ".willow", reachable=env_path is None))
    return out


def store_root_candidates() -> list[Candidate]:
    env_path = _env_path("WILLOW_STORE_ROOT")
    out = [Candidate("env:WILLOW_STORE_ROOT", env_path)]
    out.append(Candidate("home_default", paths.willow_home() / "store", reachable=env_path is None))
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
    never creates, writes, or deletes anything.

    Divergence is computed only across *reachable* candidates — a leftover
    at a path no real resolver would land on given the current environment
    is reported for visibility (``reachable: false``) but never counted
    toward "divergent", because nothing will ever read it.
    """
    reported = []
    for c in candidates:
        if c.path is None:
            continue
        reported.append({
            "source": c.source,
            "path": str(c.path),
            "exists": _exists(c.path),
            "reachable": c.reachable,
        })
    distinct_existing = sorted({
        r["path"] for r in reported if r["exists"] and r["reachable"]
    })
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
            f"{name}: {len(distinct_existing)} distinct copies are each reachable "
            f"by a real resolver under the current environment "
            f"({', '.join(distinct_existing)}) — only one is in effect "
            f"({report['resolved']}); the others are genuinely live candidates "
            "that a different call path (or a different environment) would "
            "pick up. Not resolved automatically — pick and consolidate by hand."
        )
    return report


def scan() -> dict:
    """Read-only split-brain surface across every trust-critical artifact.

    Returns ``{"status": "ok"|"warn", "artifacts": {name: report, ...}}``.
    ``status`` is ``warn`` iff any artifact has two or more genuinely
    reachable, existing, disagreeing copies. Never mutates, creates,
    resolves, or picks between candidates — report only."""
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
