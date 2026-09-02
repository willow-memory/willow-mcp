#!/usr/bin/env python3
"""Which *direction* did a vendored copy drift?

The four cross-repo sync guards (check_vendor_sync, check_subject_consent_sync,
check_mem_ratify_sync, check_nest_pipeline_sync) all answer one question: does
the vendored body still equal upstream's? That is a byte comparison, and a byte
comparison cannot tell these two apart:

  BEHIND    upstream advanced and the vendored copy stayed put. This is box
            audit theme ①, and it is exactly how the stance_friction block went
            missing. It must fail.

  AHEAD     the vendored copy carries a change whose canonical half is still an
            OPEN upstream pull request. Nothing is wrong; the two PRs merge in
            an order. Failing here trains a reader to wave the job through,
            which is the same habit that lost stance_friction in the first
            place.

Both render as "the bytes differ", so every paired canonical+vendor change has
cost somebody a diagnosis. This module buys the direction back.

AHEAD is only ever returned on a POSITIVE identification: the vendored body is
byte-equal to that file on the head of an open upstream PR. A local hand-edit
matches no PR head and is classified DIVERGED, which stays fatal — so the guard
is not weakened, only made specific. Local edits are in any case the in-repo
hash pins' job, not this one's.

History is fetched lazily: the upstream checkout is shallow, and it is only
deepened when drift has already been found, so a green run pays nothing.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from collections.abc import Callable
from pathlib import Path

# Bounds on how far we look. A vendored file that matches neither the last 200
# upstream commits nor any of the 200 most recent PR heads is not "behind by a
# lot" in any useful sense — it is diverged, and the unified diff is the better
# answer than a deeper search.
MAX_COMMITS = 200
MAX_PR_REFS = 200

BEHIND = "behind"
AHEAD = "ahead"
DIVERGED = "diverged"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Verdict:
    kind: str
    detail: str = ""

    @property
    def fatal(self) -> bool:
        """Only a positively-identified open upstream PR is forgiven."""
        return self.kind != AHEAD


def _git(repo: Path, *args: str, check: bool = False) -> str:
    try:
        p = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if check and p.returncode != 0:
        return ""
    return p.stdout


def _repo_root(start: Path) -> Path | None:
    out = _git(start, "rev-parse", "--show-toplevel").strip()
    return Path(out) if out else None


def _deepen(repo: Path) -> None:
    """Make history and PR heads available. Best-effort and idempotent."""
    if _git(repo, "rev-parse", "--is-shallow-repository").strip() == "true":
        _git(repo, "fetch", "--unshallow", "--quiet")
    _git(repo, "fetch", "--quiet", "origin",
         "+refs/pull/*/head:refs/remotes/pr/*")


def _body_at(repo: Path, rev: str, rel: str, body: Callable[[str], str]) -> str | None:
    text = _git(repo, "show", f"{rev}:{rel}", check=True)
    if not text:
        return None
    try:
        return body(text)
    except ValueError:
        return None


def classify(upstream_file: Path, mine_body: str,
             body: Callable[[str], str]) -> Verdict:
    """Explain a known-drifted file. Call only after bodies compared unequal."""
    root = _repo_root(upstream_file.parent)
    if root is None:
        return Verdict(UNKNOWN, "upstream checkout is not a git repository")
    try:
        rel = str(upstream_file.resolve().relative_to(root.resolve()))
    except ValueError:
        return Verdict(UNKNOWN, "file is outside the upstream repository")

    _deepen(root)

    # AHEAD: does an open upstream PR already carry exactly this body? Resolve
    # each ref to a blob first — that is one cheap rev-parse per ref, and many
    # PRs share a blob — then read only the distinct ones.
    refs = _git(root, "for-each-ref", "--sort=-committerdate",
                f"--count={MAX_PR_REFS}", "--format=%(refname)",
                "refs/remotes/pr/").split()
    seen: dict[str, bool] = {}
    for ref in refs:
        blob = _git(root, "rev-parse", f"{ref}:{rel}", check=True).strip()
        if not blob:
            continue
        if blob not in seen:
            found = _body_at(root, ref, rel, body)
            seen[blob] = found is not None and found == mine_body
        if seen[blob]:
            num = ref.rsplit("/", 1)[-1]
            return Verdict(AHEAD, f"upstream PR #{num}")

    # BEHIND: was this body a real upstream version at some point?
    commits = _git(root, "log", f"--max-count={MAX_COMMITS}",
                   "--format=%H", "--", rel).split()
    for sha in commits:
        found = _body_at(root, sha, rel, body)
        if found is not None and found == mine_body:
            return Verdict(BEHIND, f"upstream commit {sha[:12]}")

    return Verdict(DIVERGED, "matches no upstream commit and no open upstream PR")


def annotate(title: str, vendored_path: str, verdict: Verdict,
             resync_hint: str) -> str:
    """The GitHub annotation for a verdict, warning or error as it deserves."""
    if verdict.kind == AHEAD:
        return (f"::warning title={title} ahead of upstream::{vendored_path} does not "
                f"match upstream yet because the canonical half is still open as "
                f"{verdict.detail}. This is a merge ORDER, not drift: merge the "
                f"upstream PR, then re-run this job and it goes green untouched. "
                f"Local edits are still caught by the in-repo hash pin.\n")
    if verdict.kind == BEHIND:
        return (f"::error title={title} behind upstream::{vendored_path} is stale — its "
                f"body matches {verdict.detail}, so upstream has advanced and the "
                f"vendored copy stayed put. This is the failure that lost the "
                f"stance_friction block. {resync_hint}\n")
    return (f"::error title={title} diverged::{vendored_path} {verdict.detail}. It is "
            f"either an edit made directly to the vendored copy, or an upstream "
            f"change that was never pushed. {resync_hint}\n")
