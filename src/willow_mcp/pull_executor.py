"""willow_mcp/pull_executor.py — the broker brings a merge home; nobody types.

The third brokered git act, after :mod:`push_executor` (verb 3) and
:mod:`pr_executor` (verb 4). Gap 57f2c1762b4d: willow-bot's ``fleet_bridge``
already writes ``$WILLOW_HOME/gitsync/trigger-<owner>-<repo>.flag`` on every
push to a default branch, but the thing that used to consume it
(``~/.local/share/gitsync/gitsync-loop.py``) is the retired willow-2.0 loop,
so a merged PR stayed on GitHub until a human ran ``git pull`` — the exact
"run this in your terminal" the fleet exists to remove. The operator,
2026-09-14: *"This is the friction I'm trying to not give to users."*

**Why this is not an enveloped verb.** The syscall table's ``git.commit`` is
local history *created*; ``git.push`` is history *leaving the box*. A
fast-forward pull creates nothing and publishes nothing: it moves a local
branch to a commit the remote already holds. The desk hook already treats
``git fetch`` as read-only and lifts ``git pull``/``checkout`` for the
orchestrator seat as repo maintenance; the retired loop did the same act
unenveloped for a year. So this module takes no envelope and cites none —
it writes a plain FRANK ``git_pull`` receipt (repo, branch, before → after)
because the table's invariant is that every act leaves ink, granted or not.
If the operator later wants pull governed, that is a table edit (verb 11)
and the ``EnvelopeAuthority`` call slots in where the receipt is written.

What it refuses, because "pull" must never mean "lose work":

* a checkout whose remote is not the named repo;
* a dirty tree (tracked modifications or staged changes — untracked files
  are left alone and do not block);
* a branch that is ahead of, or diverged from, its upstream — ``--ff-only``
  would refuse anyway, but saying *why* before fetching is the point;
* a symlinked checkout; a branch name beginning with ``-``.

What it does: ``fetch`` (with the willows-bot installation token as an
``http.extraheader`` when the App covers the repo, so private repos work
and no token touches the remote URL; plain fetch otherwise), ``checkout``
the target branch if the tree is on another one, ``merge --ff-only``, and —
only when asked — ``branch -d`` the named feature branches, which git itself
refuses for anything unmerged.

Fix (gap ``3df997ffe92b``, 2026-09-22): a no-op pull (``before == after`` —
the checkout was already at ``remote/branch``, the common case for the
steward's every-tick sweep) no longer appends a ``git_pull`` receipt.
:mod:`reloader`'s confirm names a receipt by id; a no-op row minted seconds
after an operator's seal was landing, silently displacing the sealed
receipt from "newest" before the reloader's next tick could ever see it
sealed. Nothing changed, so there is nothing to request a restart onto —
``execute_pull`` reports ``changed: false``, ``receipt_id: None``, and
``reason: "no-op: already at <sha>"`` instead.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable, Optional

from . import paths

EVENT = "git_pull"

_GIT_TIMEOUT_S = 180


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, "pulled": False, **extra}


def _git(checkout: Path, *args: str, runner: Optional[Callable] = None) -> subprocess.CompletedProcess:
    run = runner or subprocess.run
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return run(
        ["git", "-C", str(checkout), *args],
        capture_output=True, text=True, timeout=_GIT_TIMEOUT_S, env=env, check=False,
    )


def _out(p: subprocess.CompletedProcess) -> str:
    return (p.stdout or "").strip()


def _tail(p: subprocess.CompletedProcess) -> str:
    return "\n".join((p.stderr or p.stdout or "").strip().splitlines()[-5:])


def _fetch_config_for_app_token(token: str) -> list[str]:
    """``-c http.https://github.com/.extraheader=...`` — the same shape the
    push uses, so the token is on argv for one subprocess and never in the
    remote URL or the config file."""
    import base64

    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return ["-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}"]


def inspect_for_pull(checkout: str | Path, *, remote: str = "origin",
                     runner: Optional[Callable] = None) -> dict:
    """Read-only facts the executor decides on. Never raises."""
    from .push_executor import _repo_matches_remote, inspect_checkout

    path = Path(checkout).expanduser()
    if path.is_symlink():
        return {"ok": False, "reason": f"refusing a symlinked checkout: {path}"}
    facts = inspect_checkout(path, remote=remote, runner=runner)
    if not facts.get("ok"):
        return facts
    # Tracked changes only: `--untracked-files=no` so a stray data/ folder or
    # a scratch file never blocks a merge from coming home.
    status = _git(path, "status", "--porcelain", "--untracked-files=no", runner=runner)
    raw = status.stdout or ""  # not stripped: porcelain's first two columns may be spaces
    facts["dirty"] = bool(raw.strip())
    facts["dirty_files"] = [line[3:] for line in raw.splitlines() if line.strip()][:20]
    facts["_matches"] = _repo_matches_remote
    return facts


def execute_pull(
    app_id: str,
    *,
    checkout: str | Path,
    repo: str,
    branch: str = "",
    remote: str = "origin",
    prune_branches: Optional[list[str]] = None,
    project: str,
    session: str = "",
    ledger=None,
    runner: Optional[Callable] = None,
) -> dict:
    """Fast-forward ``branch`` of the checkout at ``checkout`` to
    ``remote/branch`` — or refuse with the reason. ``branch`` defaults to
    the remote's HEAD branch. ``prune_branches`` are deleted with
    ``branch -d`` afterwards (git refuses anything unmerged).

    ``ledger`` is a :class:`GovernanceLedger`; a receipt is appended on
    success and on refusal alike. ``runner`` replaces ``subprocess.run``.
    """
    repo = (repo or "").strip().strip("/")
    remote = (remote or "origin").strip()
    branch = (branch or "").strip()
    prune = [b.strip() for b in (prune_branches or []) if b and b.strip()]
    if repo.count("/") != 1:
        return _refuse("EINVAL", "a pull names a repo (org/name)")
    if branch.startswith("-") or remote.startswith("-") or any(b.startswith("-") for b in prune):
        return _refuse("EINVAL", "branch, remote and prune names may not begin with '-'")

    facts = inspect_for_pull(checkout, remote=remote, runner=runner)
    if not facts.get("ok"):
        return _refuse("EINVAL", facts.get("reason", "checkout unreadable"))
    if not facts["_matches"](facts["remote_url"], repo):
        return _refuse(
            "EINVAL",
            f"checkout {facts['path']} has {remote!r} = {facts['remote_url']!r}, "
            f"which is not {repo!r}",
        )
    path = Path(facts["path"])
    if facts["dirty"]:
        return _refuse(
            "EBUSY",
            f"{path} has uncommitted tracked changes; a pull that could lose "
            f"work is not performed ({', '.join(facts['dirty_files'][:5])})",
            dirty_files=facts["dirty_files"],
        )

    # Credential: the App's installation token when it covers the repo, so a
    # private repo fetches; otherwise a plain fetch (public repos need none).
    from . import github_app_credentials as gac

    auth = gac.mint_installation_token(repo)
    cfg: list[str] = []
    auth_mode = "none"
    if auth.get("ok") and auth.get("mode") == "app":
        cfg = _fetch_config_for_app_token(auth["token"])
        auth_mode = "app"

    try:
        fetched = _git(path, *cfg, "fetch", "--prune", remote, runner=runner)
    except subprocess.TimeoutExpired:
        return _refuse("ETIMEDOUT", f"git fetch exceeded {_GIT_TIMEOUT_S}s")
    if fetched.returncode != 0:
        return _refuse("EFETCH", _tail(fetched) or f"git fetch exited {fetched.returncode}",
                       auth_mode=auth_mode)

    if not branch:
        head = _git(path, "symbolic-ref", "--short", f"refs/remotes/{remote}/HEAD", runner=runner)
        if head.returncode != 0 or not _out(head):
            return _refuse("EINVAL", f"no branch named and {remote}/HEAD is not set in {path}")
        branch = _out(head).split("/", 1)[1]
    target = f"{remote}/{branch}"

    exists = _git(path, "rev-parse", "--verify", "--quiet", f"refs/remotes/{target}", runner=runner)
    if exists.returncode != 0:
        return _refuse("EINVAL", f"{target} does not exist after fetch")
    remote_sha = _out(exists)

    local = _git(path, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}", runner=runner)
    before = _out(local) if local.returncode == 0 else ""
    if before:
        # Ahead or diverged: the local branch holds commits the remote does
        # not. --ff-only would refuse; say why before touching the tree.
        counts = _git(path, "rev-list", "--left-right", "--count",
                      f"refs/heads/{branch}...refs/remotes/{target}", runner=runner)
        if counts.returncode == 0 and _out(counts):
            ahead_s, behind_s = _out(counts).split()
            ahead, behind = int(ahead_s), int(behind_s)
            if ahead:
                return _refuse(
                    "EDIVERGED",
                    f"{branch} is {ahead} commit(s) ahead of {target}"
                    + (f" and {behind} behind" if behind else "")
                    + "; a pull that would need a merge or a reset is not performed",
                    ahead=ahead, behind=behind, sha=before,
                )

    if facts["branch"] != branch:
        switched = _git(path, "checkout", "-q", branch, runner=runner)
        if switched.returncode != 0:
            return _refuse("ECHECKOUT", _tail(switched) or f"git checkout {branch} failed")

    merged = _git(path, "merge", "--ff-only", target, runner=runner)
    if merged.returncode != 0:
        return _refuse("EFF", _tail(merged) or "fast-forward refused", sha=before)
    after_p = _git(path, "rev-parse", "HEAD", runner=runner)
    after = _out(after_p)

    pruned, kept = [], {}
    for b in prune:
        if b == branch:
            continue
        d = _git(path, "branch", "-d", b, runner=runner)
        if d.returncode == 0:
            pruned.append(b)
        else:
            kept[b] = _tail(d)

    receipt = {
        "ok": True, "pulled": before != after, "repo": repo, "branch": branch,
        "remote": remote, "before": before, "after": after, "remote_sha": remote_sha,
        "auth_mode": auth_mode, "pruned": pruned, "kept": kept, "checkout": str(path),
        "changed": before != after,
    }
    if before == after:
        # Gap 3df997ffe92b: a no-op pull (the checkout was already at
        # remote/branch — the common case for the steward's every-tick
        # sweep, and for the desk's own "confirm we're current" pull) used
        # to mint a git_pull receipt identical in shape to a real one. The
        # reloader's confirm matches a receipt by id, and a fresh no-op row
        # landing seconds after an operator's seal displaced the sealed
        # receipt from "newest" — three sealed restarts never fired because
        # of exactly this. Nothing changed, so there is nothing to request a
        # restart onto: no receipt, no ink, just the fact reported.
        receipt["receipt_id"] = None
        receipt["reason"] = f"no-op: already at {after}"
    elif ledger is not None:
        try:
            rec = ledger.append(project, EVENT, {
                "actor": app_id, "repo": repo, "branch": branch, "remote": remote,
                "before": before, "after": after, "pruned": pruned, "session": session,
                "checkout": str(path),
            })
            receipt["receipt_id"] = rec
        except Exception as exc:  # noqa: BLE001 — the pull happened; the receipt failing is reported, not hidden
            receipt["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return receipt


# ── the trigger consumer ─────────────────────────────────────────────────────

def trigger_dir() -> Path:
    """``$WILLOW_HOME/gitsync`` — where willow-bot's bridge writes trigger
    flags. Routed through :func:`paths.willow_home`, which raises
    :class:`paths.RetiredHomeError` when ``WILLOW_HOME`` is unset and the
    implicit default has been retired — callers with a receipt to fill (e.g.
    :func:`sweep_triggers`) turn that into a structured ``unreachable``, never
    an empty success reaching a dead directory."""
    return paths.willow_home() / "gitsync"


def _github_root() -> Path:
    for var in ("WILLOW_DEV_SAFE_ROOT", "GITHUB_ROOT"):
        v = (os.environ.get(var) or "").strip()
        if v:
            return Path(v).expanduser()
    return Path.home() / "github"


def _case_insensitive_dirs(parent: Path, target: str) -> list[Path]:
    """Child directories of ``parent`` whose name matches ``target`` case-
    insensitively — GitHub owner and repo names are case-insensitive, but two
    checkouts differing only by case are two different directories on disk."""
    if not parent.is_dir():
        return []
    lowered = target.lower()
    return sorted(p for p in parent.iterdir() if p.is_dir() and p.name.lower() == lowered)


def resolve_clone_status(repo: str, *, root: Optional[Path] = None,
                         runner: Optional[Callable] = None) -> dict:
    """``org/name`` -> the checkout under the github root whose ``origin`` is
    that repo, matching the owner directory and the repo directory case-
    insensitively (GitHub owner/repo names are case-insensitive; the clone on
    disk need not match the case willow-bot's trigger names): ``<root>/<org>/
    <name>`` first (the org layout this box uses), then the flat
    ``<root>/<name>``. Verified by remote URL, never by folder name alone.
    Exactly one verified match wins a layout; two candidates differing only
    by case is ``EAMBIG`` naming both, never a guess.

    Returns ``{"clone": Path|None, "error": None|"EAMBIG", "candidates": [...]}``.
    """
    from .push_executor import _repo_matches_remote, inspect_checkout

    if repo.count("/") != 1:
        return {"clone": None, "error": None, "candidates": []}
    owner, name = repo.split("/", 1)
    root = root or _github_root()

    def _verified(cand: Path) -> bool:
        if not (cand / ".git").exists():
            return False
        facts = inspect_checkout(cand, runner=runner)
        return bool(facts.get("ok")) and _repo_matches_remote(facts["remote_url"], repo)

    org_matches: list[Path] = []
    for owner_dir in _case_insensitive_dirs(root, owner):
        org_matches.extend(d for d in _case_insensitive_dirs(owner_dir, name) if _verified(d))
    if len(org_matches) == 1:
        return {"clone": org_matches[0], "error": None, "candidates": []}
    if len(org_matches) > 1:
        return {"clone": None, "error": "EAMBIG", "candidates": [str(m) for m in org_matches]}

    flat_matches = [d for d in _case_insensitive_dirs(root, name) if _verified(d)]
    if len(flat_matches) == 1:
        return {"clone": flat_matches[0], "error": None, "candidates": []}
    if len(flat_matches) > 1:
        return {"clone": None, "error": "EAMBIG", "candidates": [str(m) for m in flat_matches]}

    return {"clone": None, "error": None, "candidates": []}


def resolve_clone(repo: str, *, root: Optional[Path] = None,
                  runner: Optional[Callable] = None) -> Optional[Path]:
    """Backward-compatible wrapper over :func:`resolve_clone_status`: the
    resolved checkout, or ``None`` on no match or ambiguity."""
    return resolve_clone_status(repo, root=root, runner=runner)["clone"]


def sweep_triggers(app_id: str, *, project: str, session: str = "", ledger=None,
                   root: Optional[Path] = None, triggers: Optional[Path] = None,
                   runner: Optional[Callable] = None) -> dict:
    """Consume every ``trigger-<owner>-<repo>.flag`` willow-bot left: resolve
    the clone, pull it home, remove the flag on success. A refusal leaves the
    flag in place (so the next sweep tries again once the tree is clean) and
    is reported, never swallowed. Empty dir → ``{"swept": []}``, honestly."""
    if triggers is not None:
        tdir = triggers
    else:
        try:
            tdir = trigger_dir()
        except paths.RetiredHomeError as exc:
            return {"ok": False, "state": "unreachable", "reason": "retired_home",
                    "detail": str(exc), "swept": []}
    if not tdir.is_dir():
        return {"ok": True, "triggers_dir": str(tdir), "present": False, "swept": []}
    results = []
    for flag in sorted(tdir.glob("trigger-*.flag")):
        stem = flag.name[len("trigger-"):-len(".flag")]
        # willow-bot writes owner-repo with '/' -> '-'; owners do not contain
        # '-' in this fleet's orgs except as a real hyphen, so split on the
        # first '-' that yields an existing clone.
        repo, clone, ambiguous = "", None, None
        parts = stem.split("-")
        for i in range(1, len(parts)):
            cand = f"{'-'.join(parts[:i])}/{'-'.join(parts[i:])}"
            status = resolve_clone_status(cand, root=root, runner=runner)
            if status["clone"] is not None:
                repo, clone = cand, status["clone"]
                break
            if status["error"] == "EAMBIG":
                repo, ambiguous = cand, status["candidates"]
                break
        if clone is None:
            if ambiguous is not None:
                results.append({
                    "flag": flag.name, "ok": False, "error": "EAMBIG",
                    "reason": (
                        f"{len(ambiguous)} checkouts under {root or _github_root()} "
                        f"match {repo!r} case-insensitively: {', '.join(ambiguous)}"
                    ),
                    "candidates": ambiguous,
                })
            else:
                results.append({"flag": flag.name, "ok": False, "error": "ENOCLONE",
                                "reason": f"no checkout under {root or _github_root()} for {stem!r}"})
            continue
        out = execute_pull(app_id, checkout=clone, repo=repo, project=project,
                           session=session, ledger=ledger, runner=runner)
        out["flag"] = flag.name
        if out.get("ok"):
            try:
                flag.unlink()
                out["flag_removed"] = True
            except OSError as exc:
                out["flag_removed"] = False
                out["flag_error"] = str(exc)
        results.append(out)
    return {"ok": True, "triggers_dir": str(tdir), "present": True, "swept": results}
