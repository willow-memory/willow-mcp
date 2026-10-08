# `onescript_run_execute` — the desk runs the one script (broker, not a terminal)

**Status:** built locally with this bite. Receipt-only; no syscall row, no envelope.

## Why

The one script's first local seat run (willow-bot `one-script`, ratatosk
`--onescript`) was a sequence of shell commands. Operator, 2026-10-07: *"build
the broker verb."* An act that cannot run through Kart or a broker verb, once
bundled in the APK, is a gap (standing rule, 2026-09-16). Like
`git_pull_execute` and `pip_sync_execute`, this runs in the broker process, not
Kart: the steps read the operator's keyring export and Nestor's store and
write the box, which the Kart sandbox cannot reach.

## Shape

`onescript_run_execute(app_id, step, args=None, project="")` — one tool, a fixed
step table, no free-form argv, no shell.

| step | runs | args |
|---|---|---|
| `keys_export` | `<bot python> -m onescript keys export --from $WILLOW_HOME/verifiers.json --to $WILLOW_HOME/config/verifiers.public.json` | none |
| `checkin` | `-m onescript checkin` | none |
| `scope` | `-m onescript scope --by … [--match W=v]… [--upto N]` | `by` (W's), `match` (W -> text), `upto` |
| `seal` | `-m onescript seal SUBJECT` | `subject` (`serve:`/`proposal:` + hex), optional `pair_id` |
| `serve` | `-m onescript serve --by … --upto N --max-chars M` | scope args + `max_chars` (1..60000) |
| `rat_turn` | `ratatosk --onescript --served <box>/served.json --out <box>/proposals.jsonl --model M TASK` | `model` (installed local Ollama tag), `task` (<= 2000 chars) |
| `turn` | `-m onescript turn BITE [--proposal <box>/proposals.jsonl]` | `bite`, optional `proposals` (default true) |
| `checkout` | `-m onescript checkout` | none |

- Interpreter: `$WILLOW_HOME/venvs/willow-bot/bin/python`, cwd the willow-bot
  checkout's `one-script/` (resolved like `git_pull_execute`: verified by
  `origin`, a symlink refused). ratatosk: `$WILLOW_HOME/venvs/willow-mcp/bin/ratatosk`;
  absent -> `rat_turn` reports `unreachable` with that reason.
- Box, served file, proposals file: `<willow-bot>/.flow/onescript/…`. Keyring
  paths: `$WILLOW_HOME/verifiers.json` -> `$WILLOW_HOME/config/verifiers.public.json`.
  None is ever taken from the caller.
- Child env allowlist: `HOME PATH WILLOW_HOME NESTOR_DB WILLOW_NESTOR_DB
  ONESCRIPT_GROVE OLLAMA_HOST` (loopback only). No provider keys, no proxy
  variables, no `WILLOW_KEYRING` (the signing ring).
- Timeouts: `checkin` 300 s (it runs the tests gate), `rat_turn` 900 s, the rest
  120 s. A timeout kills the child's whole process group.
- `seal` finds the sealed pair by subject in Nestor's store (the CLI takes no
  pair id). After it runs, the verb reads which live sealed pair covers the
  subject and records that one (`pair_id`, `sealed_pair_ids`); a caller's
  `pair_id` that differs is reported as `pair_id_mismatch` + `caller_pair_id`.
- `rat_turn` truncates `proposals.jsonl` (no symlink, `O_NOFOLLOW`) before the
  run, because ratatosk only appends. A run that does not exit 0 (including a
  capped one) is `unreachable` and its partial rows are truncated away
  (`partial_rows_discarded`), never handed to `turn`.
- After a timeout the process group is killed and the pipes are drained for at
  most `DRAIN_BOUND` (5 s), then closed: a grandchild in another session cannot
  hold the call past timeout + 5 s.
- A leading `-` in free text (`task`, `bite`) is refused so it cannot parse as a flag.

## Result

`{ok, ran, step, state, exit, reason, stdout_json | tail, duration_s, args_digest, receipt_id}`.

- `populated` — exit 0 with output; `empty` — exit 0, nothing printed;
  `unreachable` — could not run to a verdict (missing prerequisite, timeout, or
  a non-zero exit; `exit` and `reason` say which). Never collapsed.
- A bad argument is refused before anything runs: `{ok: false, ran: false, error, reason}`.
- `keys_export` returns names and counts of exported / dropped entries only —
  its output is filtered to the CLI's own summary lines and any 32+ hex run is
  withheld.

## Ink

FRANK `onescript_run`: step, arguments digest (never the text), exit, duration,
state. No envelope, no egress, nothing pushed.

## ACL

Own gate name `onescript_run_execute`. In `orchestrator` only;
**not** in `full_access`, `steward_sweep` or `envelope_apply`. The `willow` desk manifest
already lists `orchestrator`, so no manifest change or
re-sign is needed to grant it. The tool is not in `DESK_CORE` (held at the
50-tool Glama cap); a desk reaches it by name.
