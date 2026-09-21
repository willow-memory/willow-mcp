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
``Path.exists()`` / ``Path.stat()`` on candidate paths, plus one
``json.loads`` of each envelope-registry copy to compare their newest entries
(gap 4c7512c57a7e). Nothing is created, written, moved, or deleted.

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
    # Gap 4c7512c57a7e: the implicit ~/.willow registry is unreachable from
    # THIS process once WILLOW_HOME is set — but a shell the operator opens
    # without WILLOW_HOME (a plain terminal, a CLI ratify) resolves it, and
    # "ratified" from there never reaches the registry this process reads.
    # Listed so scan() can compare its contents; reachable=False keeps it out
    # of the plain "divergent" count, and _shadow_registry_problem() names it
    # only when it holds something newer than the resolved registry.
    shadow = Path.home() / ".willow" / "constitutional" / "pre-approved.json"
    if _env_path("WILLOW_HOME") is not None and all(
        c.path is None or not _same(c.path, shadow) for c in out
    ):
        out.append(Candidate("implicit_home_shadow", shadow, reachable=False))
    return out


def _same(a: Path, b: Path) -> bool:
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return False


def _registry_newest(path: Path) -> tuple[str, set[str]] | None:
    """``(newest_timestamp, proposal_ids)`` across a registry's ``proposals``
    and ``active`` rows, or ``None`` when the file is absent or unreadable.
    Timestamps are the ISO strings the authoring module writes, which sort
    lexically. Read-only — one ``json.loads``, no resolver consulted."""
    import json
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    stamps: list[str] = []
    ids: set[str] = set()
    for row in (doc.get("proposals") or []):
        if isinstance(row, dict):
            ids.add(str(row.get("id") or ""))
            stamps.append(str(row.get("proposed_at") or ""))
    for row in (doc.get("active") or []):
        if isinstance(row, dict):
            stamps.append(str(row.get("issued_at") or row.get("proposed_at") or ""))
    ids.discard("")
    return (max(stamps) if stamps else ""), ids


def _shadow_registry_problem(report: dict) -> dict | None:
    """Gap 4c7512c57a7e: the ``implicit_home_shadow`` candidate is a named
    problem — not a leftover — when it holds a proposal newer than anything
    in the resolved registry, or a proposal id the resolved registry has
    never seen. That is the signature of an operator act (a CLI ratify, a
    propose from a plain shell) that landed in ``~/.willow`` while this
    process reads elsewhere. Read-only."""
    resolved = report.get("resolved")
    shadow = next(
        (c for c in report.get("candidates") or []
         if c.get("source") == "implicit_home_shadow" and c.get("exists")),
        None,
    )
    if shadow is None or not resolved:
        return None
    shadow_state = _registry_newest(Path(shadow["path"]))
    if shadow_state is None:
        return None
    resolved_state = _registry_newest(Path(resolved)) or ("", set())
    shadow_newest, shadow_ids = shadow_state
    resolved_newest, resolved_ids = resolved_state
    newer = bool(shadow_newest) and shadow_newest > resolved_newest
    unseen = sorted(shadow_ids - resolved_ids)
    if not newer and not unseen:
        return None
    return {
        "shadow": shadow["path"],
        "resolved": resolved,
        "shadow_newest": shadow_newest or None,
        "resolved_newest": resolved_newest or None,
        "unseen_proposals": unseen,
        "detail": (
            f"envelope_registry: the implicit ~/.willow registry ({shadow['path']}) "
            + (f"holds an entry from {shadow_newest}, newer than anything in the "
               f"resolved registry ({resolved_newest or 'empty'})"
               if newer else "holds proposals the resolved registry has never seen")
            + (f"; proposal ids not in the resolved registry: {', '.join(unseen)}"
               if unseen and newer else "")
            + f". This process reads {resolved}; a shell without WILLOW_HOME "
            "writes the shadow, so an operator's 'ratified' can land there and "
            "never be seen here. Not repaired automatically — consolidate by hand."
        ),
    }


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
    registry = _artifact_report(
        "envelope_registry", envelope_registry_candidates(), _resolved_envelope_registry())
    shadow_problem = _shadow_registry_problem(registry)
    if shadow_problem is not None:
        registry["shadow_problem"] = shadow_problem
        registry["status"] = "warn"
        registry["detail"] = (
            (registry["detail"] + " ") if registry.get("detail") else ""
        ) + shadow_problem["detail"]
    artifacts = {
        "envelope_registry": registry,
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
