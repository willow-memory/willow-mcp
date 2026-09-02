---
name: willow-serve
description: Turn willow-mcp OAuth HTTP serve mode on or off on request, toggling both the systemd --user service and the .mcp.json client entry
---

@markdownai v1.0

# /willow-serve

Turns willow-mcp's OAuth serve mode **on** or **off** without hand-editing
config. Wraps `scripts/willow-serve`, which manages a systemd `--user` service
for the `--serve` process and adds/removes the matching http entry in
`.mcp.json` so the MCP client connects only while serve is on.

## When to use this

- The user asks to "turn on/off", "start/stop", or "enable/disable" willow-mcp
  serve mode / the OAuth server.
- The user wants to check whether serve mode is currently running.

## Steps

@if consumer="ai"
**1. Map the request to an action.**

| User intent | Command |
|-------------|---------|
| turn on / start / enable | `scripts/willow-serve on` |
| turn off / stop / disable | `scripts/willow-serve off` |
| is it on? / status | `scripts/willow-serve status` |
| see logs | `scripts/willow-serve logs` |

**2. First run only — install the unit.** If `on` reports
`unit not installed`, run `scripts/willow-serve install` once (writes the
systemd user unit), then `on` again. Port/host default to `8765`/`127.0.0.1`;
to change them set `WILLOW_MCP_PORT` / `WILLOW_MCP_HOST` before `install`.

**Serve mode does not inherit your shell environment.** The `systemd --user`
unit is started by systemd, not your shell, so a `WILLOW_PG_DB` (or
`WILLOW_STORE_ROOT` / `WILLOW_HOME`) you `export` in `.bashrc` will **not**
reach the serve process — it falls back to defaults. On an env-configured
host this shows up as serve-mode reads failing with `table_not_found` on data
the stdio server can see. Make the config reachable before `on` — e.g.
`systemctl --user import-environment WILLOW_PG_DB WILLOW_STORE_ROOT WILLOW_HOME`
or a `~/.config/environment.d/*.conf` file. See the README "Turning serve mode
on and off" note for details.

**3. Run the command** from the repo root.

**4. After `on` or `off`, tell the user to run `/mcp`.** The `.mcp.json` entry
changed, so the client must reconnect to pick it up. On `on`, if they already
signed in once, the cached credential is reused — no OAuth screen reappears
unless the credential was cleared (that is expected, not a failure).
@endif

## What this skill will not do

@constraint severity=critical
- It does not hand-edit `.mcp.json` directly — the script owns that toggle so
  the entry and the running service never drift apart.
- It does not disable OAuth or the identity-binding gate to make serve mode
  "easier". Serve mode is auth-gated by design; leave it that way.
