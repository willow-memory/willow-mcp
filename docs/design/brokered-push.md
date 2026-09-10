# Brokered push

**Status:** slice 1 landed (push executor). Slices 2 and 3 open under gap
5ecb87cfdf56.
**Ruling:** governance record `operator-ruling-2026-09-10-kart-push-is-brokered`.

## The ruling

Who initiates a push and who holds the key are two questions with two answers.

- **Kart, or any agent, initiates.** A task commits in a worktree and ends
  with "ask for a push", never with `git push`.
- **The broker holds the credential.** willow-mcp, the app's own trusted
  process, performs the push inside the bounds of a signed `git.push`
  envelope (syscall table verb 3: repo, branches, remote, force).
- **No GitHub token ever enters the sandbox.** Not as a file, not as an
  environment variable, not through a credential prefix.

The operator's reason, in their words: the system is going to run inside an
APK. Kart needs to do things when a terminal is not available. A user having
to run git commands is a step back in usability from what most developers
need, and harder still for a user without much modern computer skill.

Under this framing the older question, "does Kart get a GitHub credential",
closes as **no, by design**, and the usability problem is solved anyway: the
user signs in once through the app, and every push after that is a consent
screen or a standing envelope, never a command.

## Slice 1: the executor (this document's landed half)

`willow_mcp/push_executor.py`, exposed as the MCP tool `git_push_execute`.

1. The checkout's remote must be the repo the envelope names (`org/name`
   against the URL tail; nothing looser). A checkout pointing elsewhere is
   refused before the envelope is consulted.
2. The exact call args go through `EnvelopeAuthority.authorize_and_cite`:
   the same indivisible check-then-cite `envelope_apply` performs. A refusal
   is cited with its errno. No subprocess runs before this point.
3. On ENOENT / EAMBIG / EEXPIRED / EDQUOT the ask is filed in the
   human-required queue (`kind: push_request`) with the field-level reason
   and the exact bounds an envelope would need. Filing never changes the
   refusal.
4. `git push <remote> <branch>` runs from the host side with
   `GIT_TERMINAL_PROMPT=0`. `--force-with-lease` only when the envelope's
   bounds carry `force: true` and the caller asked.
5. The receipt names the sha, the envelope, the citation, and git's last
   lines. Verify against the remote, not against the dict.

The tool is gated under the `envelope_apply` permission group: it is an
envelope application with the act attached, not a new capability. A group of
its own needs a `gate.py` edit and a manifest re-sign, which is outside this
slice's envelope.

## Slice 2: the explicit ask

Today the ask is a side effect of a refusal (`gate_request`'s rule: the
denial is the ask). Slice 2 lets an agent that knows it will need a push,
egress, or a permission group file the request up front, so the operator
sees it while the task is still queued. Shape from the superseded commit
db50715: `file_request(store, app_id, gate_id, reason, task_id, ttl)`. It
also adds the producer call at the permission-denial site so `perm.*`
requests have an asker, and either serves or drops the `gate_request` tool
name the willow manifest still lists.

A `push.` requestable prefix in `gates_panel` so the panel renders these
rows with the ratify-an-envelope action belongs here too.

## Slice 3: the credential

In the APK the user signs in to GitHub once (device flow); the identity
lives in the app keystore, readable by the broker only. Where the willow-bot
App covers the repo, the broker mints a per-push installation token scoped
to that one repo with a short TTL, so nothing durable is held for the push.
On the development box the executor uses the host's existing credential
helper until this lands.

## Out of scope

A git implementation that runs on Android at all. Separate and larger; this
design does not make it harder.
