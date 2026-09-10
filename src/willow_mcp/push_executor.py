"""willow_mcp/push_executor.py — the broker performs the push; the agent asks.

Operator ruling 2026-09-10 (governance record
``operator-ruling-2026-09-10-kart-push-is-brokered``): *who initiates a push*
and *who holds the key* are two questions with two answers. Kart, or any
agent, initiates. This process — willow-mcp, the app's own trusted process —
holds the credential and performs the push inside the bounds of a signed
``git.push`` envelope. No GitHub token is ever placed in the sandbox. In the
APK there is no terminal and no operator at a shell, so "the host pushes"
cannot mean a human typing ``git push``; it means this module.

What this module does, in order, and nothing else:

1. **Verify the checkout is the repo the envelope names.** ``repo`` is the
   ``org/name`` form the syscall table's verb 3 bounds use. The checkout's
   ``remote`` URL must end in that name; a checkout that points somewhere
   else is refused before the envelope is consulted, so a bounds match can
   never be earned by lying about which directory a branch lives in.
2. **Check and cite, before any subprocess.** The exact call args —
   ``{repo, branches:[branch], remote, force}`` — go through
   :meth:`EnvelopeAuthority.authorize_and_cite`, the same indivisible
   check-then-cite ``envelope_apply`` performs. A refusal leaves a FRANK
   citation with its errno and no push.
3. **File the ask on a miss.** ENOENT/EAMBIG/EEXPIRED/EDQUOT put a row in the
   human-required queue naming the repo, branch, and the field-level reason,
   so the operator sees "Kart wants to push X to Y" while the work is still
   waiting rather than after it has failed once. Filing never changes the
   refusal (the same fail-closed rule ``gate_request`` states).
4. **Push from the host side.** ``git push <remote> <branch>`` with the
   broker's own credential helper, ``GIT_TERMINAL_PROMPT=0`` so a missing
   credential is an error and not a hang, and ``--force`` only when the
   envelope granted ``force: true`` AND the caller asked for it.
5. **Return a receipt**: the sha pushed, the citation id, and git's own last
   lines. A caller that wants to verify does so against the remote, not
   against this dict's booleans.

Not here yet (gap 5ecb87cfdf56, later slices): a per-push installation token
minted from the willow-bot App, and Kart-direct initiation from inside a task
without an agent in the loop.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable, Optional

VERB = "git.push"

#: Errnos for which an ask is worth filing: the verb is real and the actor is
#: the right one; what is missing is a grant the operator could issue.
_ASKABLE = frozenset({"ENOENT", "EAMBIG", "EEXPIRED", "EDQUOT", "ENOGRANTS"})

_GIT_TIMEOUT_S = 120


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, "pushed": False, **extra}


def _git(checkout: Path, *args: str, runner: Optional[Callable] = None) -> subprocess.CompletedProcess:
    run = runner or subprocess.run
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return run(
        ["git", "-C", str(checkout), *args],
        capture_output=True, text=True, timeout=_GIT_TIMEOUT_S, env=env, check=False,
    )


def _repo_matches_remote(remote_url: str, repo: str) -> bool:
    """``org/name`` against the tail of an https or ssh remote URL.

    ``https://github.com/org/name.git``, ``git@github.com:org/name.git`` and
    the same without ``.git`` all match ``org/name``. Nothing looser: a
    substring match would let ``willow-mcp`` cover ``willow-mcp-archive``.
    """
    url = (remote_url or "").strip()
    if url.endswith(".git"):
        url = url[:-4]
    url = url.rstrip("/")
    tail = url.replace(":", "/").split("/")
    want = [p for p in (repo or "").strip().strip("/").split("/") if p]
    return len(want) == 2 and tail[-2:] == want


def inspect_checkout(checkout: str | Path, *, remote: str = "origin",
                     runner: Optional[Callable] = None) -> dict:
    """Read-only facts about ``checkout`` that the executor decides on:
    the remote URL, the current branch, and HEAD. Never raises."""
    path = Path(checkout).expanduser()
    if not (path / ".git").exists():
        return {"ok": False, "reason": f"{path} is not a git checkout (no .git)"}
    try:
        url = _git(path, "remote", "get-url", remote, runner=runner)
        branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD", runner=runner)
        head = _git(path, "rev-parse", "HEAD", runner=runner)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "reason": f"git could not be run in {path}: {exc}"}
    if url.returncode != 0:
        return {"ok": False, "reason": f"remote {remote!r} is not configured in {path}: "
                                       f"{(url.stderr or '').strip()}"}
    return {
        "ok": True,
        "path": str(path),
        "remote_url": (url.stdout or "").strip(),
        "branch": (branch.stdout or "").strip(),
        "head": (head.stdout or "").strip(),
    }


def _file_ask(app_id: str, *, repo: str, branch: str, remote: str, force: bool,
              errno: str, reason: str, fields, task_id: str, store=None) -> dict:
    """Put the ask in front of the operator. Returns ``{"queued": bool, ...}``
    and never raises — the caller is already refusing."""
    try:
        from . import human_loop
        from .db import Store

        if store is None:
            store = Store()
        detail = f"{errno}: {reason}"
        if fields:
            detail += f" (fields: {', '.join(str(f) for f in fields)})"
        # `review` is the queue's kind for "a human looks and decides"; the
        # push identity rides in source_ref (push.<repo>#<branch>) so a panel
        # can pick these rows out without a new kind in the Forge's list.
        item = human_loop.enqueue(
            store,
            kind="review",
            title=f"Push request: {repo} {branch} -> {remote}",
            summary=(
                f"{app_id or 'an agent'} asked to push branch {branch!r} of {repo} "
                f"to {remote!r}{' with force' if force else ''} and was refused: "
                f"{detail}. Ratify a git.push envelope with these bounds "
                f"(repo={repo!r}, branches=[{branch!r}], remote={remote!r}, "
                f"force={str(force).lower()}) and the agent can ask again."
            ),
            source_agent=app_id or "",
            source_ref=f"push.{repo}#{branch}" + (f"@{task_id}" if task_id else ""),
        )
        return {"queued": True, "id": item.get("id")}
    except Exception as exc:  # noqa: BLE001 — filing must never turn a refusal into a traceback
        return {"queued": False, "reason": f"could not enqueue the ask ({exc})"}


def execute_push(
    app_id: str,
    *,
    checkout: str | Path,
    repo: str,
    branch: str,
    remote: str = "origin",
    force: bool = False,
    envelope_id: str = "",
    project: str,
    session: str = "",
    task_id: str = "",
    ledger=None,
    store=None,
    runner: Optional[Callable] = None,
) -> dict:
    """Push ``branch`` of the checkout at ``checkout`` to ``remote``, under
    the ``git.push`` envelope that governs ``app_id`` — or refuse, cite the
    refusal, and file the ask.

    ``ledger`` is a :class:`GovernanceLedger`; the MCP tool builds it from
    the live Postgres, tests pass a fake. ``runner`` replaces
    ``subprocess.run`` in tests. Returns a dict with ``ok``/``pushed``; a
    refusal carries ``error`` (the errno) and ``reason``.
    """
    from .envelopes import EnvelopeAuthority, governing_envelope_ids

    branch = (branch or "").strip()
    repo = (repo or "").strip()
    remote = (remote or "origin").strip()
    force = bool(force)
    if not branch or not repo:
        return _refuse("EINVAL", "a push names a repo (org/name) and a branch")
    if branch.startswith("-") or remote.startswith("-"):
        return _refuse("EINVAL", "branch and remote may not begin with '-'")

    facts = inspect_checkout(checkout, remote=remote, runner=runner)
    if not facts.get("ok"):
        return _refuse("EINVAL", facts.get("reason", "checkout unreadable"))
    if not _repo_matches_remote(facts["remote_url"], repo):
        return _refuse(
            "EINVAL",
            f"checkout {facts['path']} has {remote!r} = {facts['remote_url']!r}, "
            f"which is not {repo!r}; the envelope names a repo, so the checkout "
            f"must be that repo",
        )
    exists = _git(Path(facts["path"]), "rev-parse", "--verify", "--quiet",
                  f"refs/heads/{branch}", runner=runner)
    if exists.returncode != 0:
        return _refuse("EINVAL", f"branch {branch!r} does not exist in {facts['path']}")
    sha = (exists.stdout or "").strip()

    call_args = {"repo": repo, "branches": [branch], "remote": remote, "force": force}

    # Resolve which grant to charge — the same discipline as
    # server._enveloped_verb_gate: a caller may name one of ITS OWN governing
    # grants to disambiguate, never reach one it does not hold.
    try:
        matches = governing_envelope_ids(VERB, app_id)
    except (OSError, ValueError) as exc:
        return _refuse("EAMBIG", f"envelope registry unreadable: {exc}")
    if envelope_id:
        if envelope_id not in matches:
            result = _refuse("ENOENT",
                             f"envelope {envelope_id!r} does not govern {VERB} for "
                             f"{app_id!r}", envelope_ids=matches)
            result["ask"] = _file_ask(app_id, repo=repo, branch=branch, remote=remote,
                                      force=force, errno="ENOENT", reason=result["reason"],
                                      fields=None, task_id=task_id, store=store)
            return result
        matches = [envelope_id]
    if not matches:
        result = _refuse("ENOENT", f"no active {VERB} envelope governs {app_id!r}")
        result["ask"] = _file_ask(app_id, repo=repo, branch=branch, remote=remote,
                                  force=force, errno="ENOENT", reason=result["reason"],
                                  fields=None, task_id=task_id, store=store)
        return result
    if len(matches) > 1:
        return _refuse("EAMBIG", f"multiple active {VERB} envelopes govern {app_id!r} — "
                                 "pass envelope_id to name which one to cite",
                       envelope_ids=matches)
    if ledger is None:
        return _refuse("EAMBIG", "no governance ledger: a push that cannot be cited "
                                 "is not performed")

    # Check and cite, before any subprocess. The refusal's own citation is
    # the record that the push was asked for and not granted.
    result = EnvelopeAuthority(ledger).authorize_and_cite(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
        project=project, session=session,
    )
    if not result.get("ok"):
        errno = result.get("errno", "EAMBIG")
        out = _refuse(errno, result.get("reason", ""), envelope_id=matches[0],
                      citation_id=result.get("citation_id"),
                      fields=result.get("fields"))
        if errno in _ASKABLE:
            out["ask"] = _file_ask(app_id, repo=repo, branch=branch, remote=remote,
                                   force=force, errno=errno, reason=out["reason"],
                                   fields=result.get("fields"), task_id=task_id,
                                   store=store)
        return out

    args = ["push"]
    if force:
        # Only reachable when the envelope's bounds carry force: true — the
        # check above matched call_args.force against the grant.
        args.append("--force-with-lease")
    args += [remote, f"{branch}:{branch}"]
    try:
        pushed = _git(Path(facts["path"]), *args, runner=runner)
    except subprocess.TimeoutExpired:
        return {"ok": False, "pushed": False, "error": "ETIMEDOUT",
                "reason": f"git push exceeded {_GIT_TIMEOUT_S}s", "envelope_id": matches[0],
                "citation_id": result.get("citation_id"), "sha": sha}
    tail = "\n".join((pushed.stderr or pushed.stdout or "").strip().splitlines()[-5:])
    if pushed.returncode != 0:
        return {"ok": False, "pushed": False, "error": "EPUSH",
                "reason": tail or f"git push exited {pushed.returncode}",
                "envelope_id": matches[0], "citation_id": result.get("citation_id"),
                "sha": sha}
    return {
        "ok": True, "pushed": True, "repo": repo, "branch": branch, "remote": remote,
        "force": force, "sha": sha, "envelope_id": matches[0],
        "citation_id": result.get("citation_id"), "git": tail,
        "checkout": facts["path"],
    }
