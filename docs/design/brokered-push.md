# Brokered push

**Status:** slice 1 landed (push executor). Slice 3 credential path landed
(willows-bot installation token in the broker). Slice 2 (explicit ask) still
open under gap 5ecb87cfdf56.
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

**Landed (2026-09-15, gap `5ecb87cfdf56`, denial-site half).** The producer
side is done. `gate_request`'s denial-is-the-ask rule holds; the missing
step was that the denial sites did not call the producer. They do now:
`willow_bot`-style `_file_ask` calls run in `push_executor`, `pr_executor`,
`web_egress`, `federation_egress`, and `integrations` — every refusal
with an `_ASKABLE` errno (ENOENT, EAMBIG, EEXPIRED, EDQUOT, ENOGRANTS)
enqueues a `human_required` row naming the repo, the branch, the exact
bounds an envelope would need, and the actor. The operator sees the ask
while the work is still waiting. This is `gate_request`'s "wrong-shape
tool" alternative from the module docstring: the producer is the
denial site, not an agent-facing MCP tool.

**Wrong-shape tool name is not being re-adopted.** The design once
imagined an `agent_request_gate` MCP tool. `gate_request.py`'s docstring
explains why it is the wrong shape (a tool whose whole purpose is to put
a row in front of a tired operator is one `full_access` typo away from a
phishing surface, which is why `PERM_NEVER_REQUESTABLE` exists). No
manifest under `src/willow_mcp/bundle/` declares such a tool. If an
operator's per-installation `$WILLOW_HOME/mcp_apps/<app_id>/manifest.json`
still lists one from an older manifest, that is per-installation
cleanup: remove the entry, the server was never going to serve it.

**Still open under gap `5ecb87cfdf56`** — slice 2 is not closed by the
denial-site half alone:

- **Upfront `file_request` API.** The producer today only fires as a
  side effect of a refusal. Slice 2's original shape is
  `file_request(store, app_id, gate_id, reason, task_id, ttl)` — a way
  for an agent that knows in advance it will need a push, an egress, or
  a permission group to put the ask in front of the operator BEFORE it
  hits the denial site. Not yet built.
- **Producer at `perm.*` denial sites.** Every non-envelope permission
  refusal (the manifest ACL denies a tool, a permission group is
  missing) still exits with no row filed. Add the producer at
  `gate.check_permission` and its callers.
- **`push.` requestable prefix in `gates_panel`.** The panel already
  knows how to render `perm.*` and `net.*` request rows; a `push.*`
  prefix so the ratify-an-envelope action is one click from the
  request belongs here.

## Slice 2b: closing the gap

The gap closes when the three bullets above land (or an operator
explicitly defers them with a written note). This doc reconciliation is
not itself the close.

## Slice 3: the credential

In the APK the user signs in to GitHub once (device flow); the identity
lives in the app keystore, readable by the broker only. Where the willows-bot
App covers the repo, the broker mints a per-push installation token scoped
to that one repo with a short TTL (`github_app_credentials.mint_installation_token`),
and `push_executor` authenticates the single `git push` via
`http.https://github.com/.extraheader` — nothing durable, nothing in Kart.
The App must grant **Contents: Read and write** or the executor refuses with
`EPERM` (read-only Contents cannot push). If the App is not configured or not
installed on the repo, the executor falls back to the host credential helper.

## Out of scope

A git implementation that runs on Android at all. Separate and larger; this
design does not make it harder.
