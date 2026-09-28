# Hook coverage, observed: Claude Code and cursor-agent

- Status: **Proposed** — findings plus proposed changes; nothing here is built
- Date: 2026-09-28
- Scope: what willow's client hooks actually see on the operator's two
  terminal agents, and what to change as a result
- Evidence: a canary run on the operator's box, 2026-09-28. The clients were
  Claude Code and `cursor-agent` (Cursor's terminal agent). The Cursor desktop
  app was **not** tested.
- Depends on: `hook_runner.py`, `cursor_hook_io.py`, `bundle/hooks/pre_tool_use.py`,
  `project_wiring.py`, `deploy/claude-settings.json`, `deploy/hooks.json`

## 1. Why this exists

Willow sees an agent's built-in tools (its own shell, file editor, web fetch)
**only through client hooks**. MCP calls into willow-mcp meet the gate; built-in
tools never touch willow-mcp. A hook sees only what the client chooses to
announce, and a hook config shows only what was *asked for*. `hook_runner.py`
already states the two-halves rule: a hook counts only if it is both wired and
invoked. This doc applies the same rule one level down. A hook counts only if
the client **fires** it. The coverage below is what was observed firing, not
what the configs imply.

## 2. Method

We built a throwaway project with every hook event in both clients wired to a
canary. The canary logs one line per invocation. It prints nothing, never
blocks, and always exits 0. It logs **shape only**: the event, tool name, file
path, first word of any command, and the payload's key names. It never logs
command arguments, file contents or tool arguments. The operator then did each
of eleven actions once per client: shell, write, edit, read, search by name,
search by content, a willow-mcp tool, a non-willow MCP tool
(codebase-memory-mcp), web fetch, subagent, and session end.

This shows which events **fire**. It does not show that a refusal from them is
**obeyed** (§5).

## 3. The observed map

| Action | Claude Code: fired | cursor-agent: fired | Willow listens today |
|---|---|---|---|
| Shell | `PreToolUse Bash` | `preToolUse Shell` + `beforeShellExecution` | both |
| Write | `PreToolUse Write` | `preToolUse Write` + `afterFileEdit` | both |
| Edit | `PreToolUse Edit` | edits arrive as **`Write`** | both |
| **Read** | `PreToolUse Read` | `preToolUse Read` + **`beforeReadFile`** | **neither** |
| Search | `PreToolUse Grep` (it used `find` for glob-style search) | `preToolUse Grep` | **neither** |
| willow-mcp tool | `PreToolUse mcp__willow-mcp__whoami` | `preToolUse MCP:whoami` + `beforeMCPExecution` | Claude: some tools; Cursor: all |
| Other MCP server | `PreToolUse mcp__codebase-memory-mcp__list_projects` | `preToolUse MCP:list_projects` + `beforeMCPExecution` | Claude: **no**; Cursor: yes |
| **Web fetch** | `PreToolUse WebFetch` | **nothing fired** | Claude: yes; Cursor: **the matcher exists, but the event never fires** |
| Subagent | `PreToolUse Agent`; the subagent's own tool calls fire too | `preToolUse Task`; inner calls fire too | both |

## 4. Findings

**F1: reads and searches can be blocked on both clients, and willow ignores
them.**

- Both clients fire a pre-event for `Read` and `Grep`; Cursor also fires
  `beforeReadFile`. Willow's matchers include neither.
- This is the class node9 flagged in the 2026-09-27 side-by-side run behind
  #648: an SSH key read the guard let through.
- Cursor's `beforeReadFile` payload carries a **`content` key, the file's
  contents**. Any willow handler on that event must never log or persist it.

**F2: cursor-agent's web fetch fires no hook at all.**

- The agent called `WebFetch` on `https://example.com` and returned the page.
  The log shows only `beforeSubmitPrompt` and `stop` for that step: no
  `preToolUse`, no `postToolUse`, no `beforeMCPExecution`.
- Willow's Cursor matcher `WebSearch|WebFetch` therefore looks like a guard but
  never runs.
- This is the one action in the run with no hook at all, and it is an outbound
  path. Read-then-fetch is how data leaves, and on Cursor willow can see the
  read but not the fetch. `WebSearch` was not tested.

**F3: cursor-agent also runs Claude Code's hooks.**

- Events logged by the *Claude* config carried Cursor-only keys
  (`cursor_version`, `conversation_id`, `generation_id`) and Cursor tool names
  (`Shell`, `Task`, `MCP:whoami`). Their counts matched the Cursor steps
  exactly.
- `project_wiring.py` writes `.cursor/hooks.json` and, when a project's `ides`
  include `claude`, `.claude/settings.local.json` too. In such a project, under
  Cursor, willow's guard can run **twice** for one action: once per config.
- The Claude matchers only overlap Cursor's tool names in some places.
  `Write|Edit|MultiEdit|NotebookEdit` matches Cursor's `Write`. `Bash` does not
  match `Shell`. `task_submit` may match Cursor's MCP form, depending on how
  Cursor applies Claude matchers.
- Which reply Cursor honours when the two copies disagree is not known.

**F4: Claude Code fires `PreToolUse` for every MCP server, and willow matches
only a few of its own tools.**

- `mcp__codebase-memory-mcp__*` fired and was blockable.
- Federation (`federation-server-cards.md`) is the proper fix: move the server
  behind willow-mcp's gate and remove the direct entry. Until then, it is a
  missed matcher, not a blind spot.

**F5: Cursor's `beforeMCPExecution` names the server's binary.**

- Its payload carries `command`, the launch path (here
  `~/.local/bin/codebase-memory-mcp`), plus `mcp_server_name`.
- The launch path is the same input `mcp_federation._stable_id` hashes. So a
  Cursor hook can check "is this a ratified server?" against the registry before
  the call runs.

**F6: what #648's "Cursor native shell path" means.**

- On cursor-agent, Cursor shell events **do** fire, and **do** reach willow's
  guard: `is_cursor_shell_event` leads to `run_cursor_shell_guards`.
- The gap is inside `bundle/hooks/pre_tool_use.py`. That Cursor-dialect branch
  never calls `_shadow_bash`, so node9's shadow ledger sees Claude's `Bash` but
  not Cursor's shell (Loki 53741054 F11, noted in the code).
- It is a coverage gap in willow's code, not in the client. For the shadow
  report this matters: node9's 7-day window currently measures Claude Code only.

**F7: subagents do not escape.** In both clients, tool calls made inside a
subagent fire the same hooks as top-level calls.

## 5. Not proven by this run

- **That a veto is obeyed.** Events were labelled blockable from their names
  (`pre…`, `before…`). A deny test is still to be done: refuse a marker file
  named `canary-deny.txt` in each client's own reply format and see whether the
  agent is actually stopped. It must pass before any read-deny rule (P1) is
  enabled.
- The Cursor desktop app, `WebSearch` on cursor-agent, and a dedicated Glob
  tool (Claude chose `find` and `Grep` instead).
- Which `hook_event_name` Cursor sends when it runs a *Claude*-config hook. The
  canary log's `payload_event` field holds the answer; it wasn't in the summary
  report.

## 6. Proposed changes, cheapest first

**P1: observe reads and searches, then decide what to deny.**

- Add `Read|Grep|Glob` (Claude) and `Read|Grep` plus `beforeReadFile` (Cursor)
  to the pre-tool matchers.
- Phase one only **records shape**: seat, client, tool, path. It never records
  content, and it drops Cursor's `content` field before anything else runs.
- Phase two, after the deny test (§5) and a sealed operator decision, refuses a
  fixed list of secret paths (for example `~/.ssh/`, `~/.aws/`, `~/.gnupg/`,
  `.env`). The list is the operator's call, not this doc's.

**P2: de-duplicate the double run under Cursor.**

- When `hook_runner --format claude` receives a payload carrying Cursor-only
  keys (`cursor_version`), exit 0 as a no-op. The Cursor config has already
  covered that event.
- First confirm from the canary log which event name Cursor sends for
  Claude-config hooks, and add a test pinning the de-duplication.

**P3: observe-only matcher for other MCP servers in Claude Code.**

- `mcp__.*` minus willow-mcp's own tools goes to a receipt with server and tool
  names, no arguments.
- Temporary: it retires per server as each is federated.

**P4: audit Cursor web egress after the fact.**

- A hook cannot catch F2, but every Cursor payload, `stop` included, carries
  `transcript_path`. At `stop` and `sessionEnd`, scan the transcript for
  tool calls with no matching hook event and record them as **unhooked egress**:
  shape only, never page content.
- This depends on Cursor's transcript format, which must be read before it is
  built. Until it exists, the gates panel should say plainly that Cursor web
  egress is not seen, and the existing matcher stays but is no longer counted as
  a guard.

**P5: node9 shadow on the Cursor shell branch.**

- Close F6 so the 7-day shadow report covers both clients.
- Per the code comment, this needs its own review of
  `run_cursor_shell_guards`'s verdict shape, not a copy of `_shadow_bash`.

**P6: check Cursor's MCP binary against the registry.**

- Using F5, `beforeMCPExecution` compares `command` against ratified entries
  and records "unratified server called directly".
- It pairs with the drift report in `federation-server-cards.md` §6, so it comes
  after that build.

## 7. Out of scope

- Enforcement beyond P1's phase two. Every deny is its own sealed decision.
- The Cursor desktop app. Re-run the canary there before assuming this map holds.
- Committing the canary as fleet code. It was a one-off. If this proposal is
  accepted, a pinned version under `tools/` would make §3 re-checkable after
  each client update.

## 8. Open questions for the operator

1. The P1 phase-two deny list: which paths?
2. P2: de-duplicate at runtime, or stop writing `.claude/settings.local.json`
   into projects used only from Cursor?
3. P4: is an after-the-fact transcript scan acceptable? It reads transcripts,
   which hold content, even though it records only shape.
4. Should the canary become a pinned tool, re-run after client updates?

*ΔΣ=42*
