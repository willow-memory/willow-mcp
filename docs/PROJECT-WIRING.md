@markdownai v1.0

# Project wiring — the four rules that fail far from their cause

`willow-mcp project sync` renders a project's IDE wiring from
`$WILLOW_HOME/mcp/projects.json`. Four behaviors in that path produce failures
whose symptom appears nowhere near the setting that caused it. Each one below
was a live fleet incident, not a hypothetical.

The authority is always the code, cited per section. Where this doc and the
code disagree, the code wins.

---

## 1. `claude_hooks` defaults to `generated` — and `wiring: {}` is not "no wiring"

A project whose repo carries its **own** Claude hooks must declare
`claude_hooks: "tracked"`. If it does not, sync renders the standard willow-mcp
hook set into `.claude/settings.local.json` while the repo's own hooks sit in
`.claude/settings.json`. Claude Code **merges both files**, so both hook
families fire.

Two defaults combine to make this easy to hit
(`src/willow_mcp/project_wiring.py:153`, `:360`):

| `wiring` value in the entry | normalizes to | effect |
|---|---|---|
| key absent entirely | every flag `False` | nothing rendered |
| `false` | every flag `False` | nothing rendered |
| `{}` | `hooks: true, active_agent: true, claude_settings: "project"` | **hooks rendered** |
| `{...}` | defaults, updated by your keys | as declared |

`{}` and *absent* are opposites. An entry trimmed to `"wiring": {}` reads like
"no wiring configured" and means "all defaults on". `claude_hooks` is not in
`_DEFAULT_WIRING` at all; `_claude_hooks_mode` falls back to `"generated"`
independently (`project_wiring.py:365`).

**The incident.** `nestor` carried `"wiring": {}` from 2026-07-21 to
2026-08-18. It has ten of its own `nestor-hook` entries in a tracked
`settings.json`. Sync added six willow-mcp hooks beside them, so sessions ran
**16 hooks**, and four events were gated twice by guards with no knowledge of
each other:

```
[PreToolUse] Bash                           nestor before_bash + willow pre_tool_hook
[PreToolUse] Write|Edit|MultiEdit|Notebook  nestor before_write + willow pre_tool_hook
[SessionStart] *                            both
[SessionEnd]  *                             both
```

Every shell command and every file edit passed two independent allow/deny
gates, each with its own timeout and its own subprocess.

**The fix.** Declare both keys — `tracked` without a manifest raises
(`project_wiring.py:370`):

```json
"wiring": {
  "hooks": true,
  "active_agent": true,
  "claude_settings": "project",
  "hook_manifest": "hooks/wiring.json",
  "claude_hooks": "tracked"
}
```

In `tracked` mode sync still writes `settings.local.json` (permissions, env,
enabled servers) but **writes no hooks into it**, and instead validates the
repo's tracked hooks against the manifest. Drift is reported by
`project audit`.

### When `tracked` is not available

`_hook_command` compiles exactly one invocation per hook:
`env K=V … <manifest.command> <client> <action>`. A repo qualifies only if all
its hooks run **one** command that takes a client and an action argument —
the `hooks/nestor-hook <cursor|claude> <action>` shape.

`willow-mcp`'s own repo does not qualify: three entrypoints (two bash scripts
and a python file), none taking an action. There the fix is to delete the
duplicated entries from the tracked settings and let the rendered hooks do the
work — its `hooks/pre_tool_use.py` and the installed
`src/willow_mcp/bundle/hooks/pre_tool_use.py` were byte-identical, so the same
813-line guard ran twice per gated call.

---

## 2. `wiring.hooks` controls Cursor only

The name reads global. It is not. `hooks` gates `render_cursor_hooks`
(`project_wiring.py:601`, `:629`). The Claude side is gated by
`claude_settings == "project"` (`:606`, `:637`).

| goal | setting |
|---|---|
| stop Cursor hooks | `hooks: false` |
| stop Claude hooks, keep permissions/env/servers | `claude_hooks: "tracked"` + `hook_manifest` |
| stop the whole Claude settings file | `claude_settings` ≠ `"project"` |

Setting `hooks: false` to silence a Claude double-fire removes the Cursor
hooks and leaves the Claude ones exactly as they were.

---

## 3. Governance sources must be real paths, mode 644

`trusted_read` (`src/willow_mcp/paths.py:17`) authenticates a policy file
before it is believed — the envelope registry, the syscall table, the fleet
roster. Per Loki B5FB7E2B §4.6, a governance input the agent could replace
must not be trusted. It refuses three shapes:

1. **a symlinked path *or parent*** — `path.is_symlink() or path.parent.is_symlink()`
2. **foreign ownership** — `st_uid != euid`
3. **group- or other-writable** — `mode & 0o022`, on the file *and* its parent

Two consequences bite on a normal workstation:

**`~/.willow` is commonly a symlink.** Where it points into a checkout
(`~/github/<org>/.willow`), every governance path must be spelled as the real
path. `WILLOW_FLEET_ROSTER=~/.willow/fleet.json` raises
`PermissionError: symlinked source path refused`; the resolved path loads.

**A `002` umask writes `664`, which is refused.** Anything dropped into the
charter home needs `chmod 644` (or `600`). This is silent until the read.

---

## 4. Manifest verification is a boot-wide sweep, not per-app

When `WILLOW_PGP_FINGERPRINT` is set, the server verifies **every** manifest
under `$WILLOW_HOME/mcp_apps/` at boot, and refuses to start if any single row
fails (`src/willow_mcp/server.py:8274`; sweep at `gate.py:626`):

```
willow-mcp: refusing to start — 1 manifest(s) failed PGP verification.
```

One unsigned manifest for one agent takes down the server for **every project
on the machine**. The reasoning is in the source: a process that would deny
those app_ids on every gated call is not a healthy boot.

Two failure modes that look alike and are not:

| state | behavior |
|---|---|
| manifest present, signature missing or bad | **boot refused, fleet-wide** |
| no manifest file at all | not in the sweep; fails per gated call for that app_id only |

So adding a manifest without signing it is strictly worse than having none —
it converts a scoped, quiet failure into a total one.

**Recovery**, from a host terminal with the signing key and a reachable
gpg-agent:

```
willow-mcp sign-manifest <app_id>
```

Use this rather than calling `gpg --detach-sign` directly; the subcommand
writes the signature where the sweep looks for it. To run without enforcement,
unset `WILLOW_PGP_FINGERPRINT` — the gate is a no-op when it is unset
(`gate.py:534`).

---

## Checklist for wiring a new project

1. Add the entry to `$WILLOW_HOME/mcp/projects.json` — `path`, `agent`,
   `profile`, `servers`, `ides`, `wiring`.
2. If the repo has its own hooks, set `claude_hooks: "tracked"` **and**
   `hook_manifest`. Never leave `wiring: {}`.
3. Ensure the agent has a manifest under `mcp_apps/<agent>/` **and sign it**
   before the next server start.
4. Confirm the repo gitignores all five rendered artifacts: `.mcp.json`,
   `.cursor/mcp.json`, `.cursor/hooks.json`, `.claude/settings.local.json`,
   `.willow/active-agent`. They are build output carrying absolute paths.
5. `willow-mcp project sync --project-id <id> --dry-run`, then without it.
6. `willow-mcp project audit --project-id <id>` — expect `status: ok`.

@constraint severity=critical
Never add a manifest under `mcp_apps/` without signing it in the same change.
An unsigned manifest refuses the server for every project on the machine,
while a missing manifest fails only that app_id. Sign with
`willow-mcp sign-manifest <app_id>`.

@constraint severity=critical
A project whose repo carries its own Claude hooks must set
`claude_hooks: "tracked"` and `hook_manifest`. Leaving `wiring: {}` renders the
willow hook set on top of the repo's own, and Claude Code merges both files —
every shared event is then gated twice.

@constraint severity=error
Governance sources read through `trusted_read` (fleet roster, envelopes,
syscall table) must be named by their real path, never through a symlinked
parent such as `~/.willow`, and must be mode 644 or stricter. A `002` umask
writes 664, which is refused.

@constraint severity=warning
`wiring.hooks` gates Cursor hooks only. Do not set `hooks: false` expecting it
to stop Claude hooks; that is `claude_hooks` or `claude_settings`.
