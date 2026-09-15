# Brokered push

**Status:** slice 1 landed (`git_push_execute` and `pr_open_execute`). Slice 3
credential path landed (willows-bot installation token in the broker). Slice 2
is **partly** landed: denial-site producers enqueue lease asks and brokered
git/pr misses file human-required rows; proactive `file_request`, the `perm.*`
permission-denial producer, and a `push.` requestable prefix remain open under
gap 5ecb87cfdf56.
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

## Slice 1: the executors (this document's landed half)

`willow_mcp/push_executor.py` (`git_push_execute`) and
`willow_mcp/pr_executor.py` (`pr_open_execute`) share the same brokered
shape: the agent names the act; the broker holds the credential and cites the
envelope before any subprocess or HTTP.

1. The checkout's remote must be the repo the envelope names (`org/name`
   against the URL tail; nothing looser). A checkout pointing elsewhere is
   refused before the envelope is consulted. (`pr_open` skips checkout
   inspection; it validates repo/branch names only.)
2. The exact call args go through `EnvelopeAuthority.authorize_and_cite`:
   the same indivisible check-then-cite `envelope_apply` performs. A refusal
   is cited with its errno. No subprocess or GitHub call runs before this
   point.
3. On errno in `_ASKABLE` (`ENOENT`, `EAMBIG`, `EEXPIRED`, `EDQUOT`,
   `ENOGRANTS`) the ask is filed in the human-required queue (`kind=review`,
   with `source_ref` `push.<repo>#<branch>` or `pr.<repo>#<head>`) carrying
   the field-level reason and the bounds an envelope would need. Filing never
   changes the refusal.
4. Push: `git push <remote> <branch>` runs from the host side with
   `GIT_TERMINAL_PROMPT=0`. `--force-with-lease` only when the envelope's
   bounds carry `force: true` and the caller asked. PR: the broker POSTs to
   GitHub as willows-bot under the `pr.open` envelope.
5. The receipt names the outcome (sha or PR URL), the envelope, the citation,
   and the tool output. Verify against the remote, not against the dict.

The tools are gated under the `envelope_apply` permission group: each is an
envelope application with the act attached, not a new capability. A group of
its own needs a `gate.py` edit and a manifest re-sign, which is outside this
slice's envelope.

## Slice 2: the explicit ask

`gate_request` (`open_request`, `request_lease`, `note_for_lease_denial`)
implements the seam in `docs/design/egress-request-seam.md`: the producer is
the **denial site**, not an agent-facing MCP tool. The denial is unchanged;
the ask is a side effect when enqueue succeeds.

### Landed: denial-site producers

**Lease misses** enqueue a `lease.<app_id>` gate request (visible in
`willow-mcp gates`):

- `server.task_submit` — when capability and standing consent pass but the
  egress lease is not active, calls `gate_request.request_lease` with a stable
  task digest.
- `web_egress.egress_denial`, `federation_egress.egress_denial`, and
  `integrations.egress_denial` — append `gate_request.note_for_lease_denial`
  to the refusal; that path calls `open_request` for `lease.<app_id>` only.
  These three modules do **not** call `_file_ask` and do not key off envelope
  errno.

**Brokered git/pr envelope misses** enqueue a human-required row through each
executor's `_file_ask` when the cited errno is in `_ASKABLE`:

- `push_executor.execute_push` (`git_push_execute`)
- `pr_executor.execute_pr_open` (`pr_open_execute`)

No other module runs `_file_ask` today.

### Still open

Slice 2 also covers an agent that knows it will need a push, egress, or a
permission group filing the request **up front** while the task is still
queued. Shape from the superseded commit db50715:
`file_request(store, app_id, gate_id, reason, task_id, ttl)` — not built.

Still to land:

- the producer at the **permission-denial** site (`gate.permitted` refuses a
  tool) so `perm.*` gate rows have an asker;
- either serve or drop the `gate_request` tool name the willow manifest still
  lists;
- a `push.` requestable prefix in `gates_panel` so the panel renders brokered
  push asks with the ratify-an-envelope action.

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
