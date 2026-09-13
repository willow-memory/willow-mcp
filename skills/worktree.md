---
name: worktree
description: Every code change goes through a feature branch and PR — no direct master commits
---

@markdownai v1.0

# /worktree — Branch + PR (required)

**Hard constraint.** Every change goes through a feature branch and a pull request.
Direct commits to `master` / `main` are banned — no exceptions, including "quick fixes."

---

## Pre-code checklist (run before editing)

1. **On a feature branch?** `git branch --show-current` — if `master`/`main`, stop.
2. **PR destination exists?** Branch must push to GitHub and merge via PR + CI + operator approval.

If either answer is no:

```bash
git checkout -b feat/<slug>    # or fix/ chore/ hotfix/
```

Then proceed.

```text
fork_create(app_id="hanuman", title="<title>", created_by="hanuman", topic="<slug>")
fork_log(app_id="hanuman", fork_id="<id>", component="git", type="branch", ref="feat/<slug>")
```

Check open forks before starting: `fork_list(app_id="hanuman", status="open")`

---

## Start work

```bash
git checkout -b feat/<slug>
# optional isolated directory:
git worktree add worktrees/<slug> -b feat/<slug>
```

Branch naming: `fix/<slug>` · `feat/<slug>` · `chore/<slug>` · `hotfix/<slug>`

Add `worktrees/` to `.gitignore` if you use worktree directories.

---

## During work

- All commits on the feature branch only.
- Shell mutations that need review → `task_submit` (Kart), not ad-hoc agent Bash, when
  the repo policy requires it.
- Read-only git/gh on the operator desk is fine: `git status`, `git log`, `git diff`,
  `gh pr view`, `gh pr list`.

---

## Open PR

Push is **brokered** — the seat asks; willow-mcp holds the credential and runs `git`.
Never `git push` in Bash and never with a token in Kart.

```
git_push_execute(app_id="<seat>", repo="<org>/<name>", branch="feat/<slug>", remote="origin")
```

Requires a signed `git.push` envelope (or a `human_required` ask when one is
missing). The broker mints the willows-bot installation token per push and
never puts it in Kart. See `docs/design/brokered-push.md`.

PR creation is a broker or operator-desk act — `gh pr create` on the
orchestrator seat, or a steward flow through willow-bot. `gh pr create` in an
agent Bash is blocked by the same hook that blocks `git push`.

CI must pass. Operator approves. Then merge.

---

## Teardown after merge

```text
fork_merge(app_id="hanuman", fork_id="<id>", outcome_note="merged to master")
```

```bash
git checkout master && git pull --ff-only
git branch -d feat/<slug>
git worktree remove worktrees/<slug>   # if used
git worktree prune
```

### Worktree cleanup on the host

A worktree directory may be bind-mounted into Kart sandboxes — `rm` / `git worktree remove`
from **inside** bwrap can return EBUSY. Host-side cleanup is allowed:

```bash
rm -rf ~/github/<repo>/worktrees/<slug>
git -C ~/github/<repo> worktree prune
```

---

## willow-mcp home overlays

Registry-owned manifest fields come from `bundle/config/specialists.json`. Operator
overrides live in `$WILLOW_HOME/config/specialists.json`. After pulling a release
that changes orchestrator permissions:

```bash
# merge orchestrator_seat.permissions from bundle, then:
willow-mcp-compile --force
```

---

## Why

- Direct master commits bypass CI and review.
- Rollback is messy; the ledger of what shipped becomes untrustworthy.
- Urgent work gets a `hotfix/<slug>` branch — same rule, faster name.

## Constraints

@constraint severity=critical
Every change goes through a feature branch and a pull request. Direct commits to `master` / `main` are banned — no exceptions, including "quick fixes."
