# Grove activation rail — slice 1 (surface-only)

## The gap this closes

Before this slice, `dispatch_send` wrote a dispatch packet to disk
(`meta.json`, `assignment.md`, `status.json` under `dispatch/<ID>/`) and
optionally mirrored its routing/status into Postgres
(`_pg_mirror_upsert`, `WILLOW_MCP_DISPATCH_MIRROR`), but posted **nothing**
to the Grove bus. A dispatched seat only ever found out about its packet by
polling — `dispatch_list`/`session_enter` — never by being told. Meanwhile
ratatosk's `SeatDaemon`/`BusListener` already had a complete WAKE-envelope
path: `BusListener._handle_wake` calls a pluggable `activate(env)` callback
on receipt of an `Intent.WAKE` envelope. Nothing in willow-mcp ever posted
a WAKE, and `activate` had no real implementation — `daemon.default_activate`
is an explicit no-op placeholder. And the only daemon actually running in
production, `seal_daemon.run_seal_watch_forever`, watches the Nestor seal
ledger **alone** — no Grove bus, no channel, no `activate` wired at all.

Three gaps, closed here:

1. **`dispatch_send` never posts a wake.** Fixed by
   `grove_tools.post_wake_envelope`, called from `dispatch.dispatch_send`
   right after the packet write and the PG mirror.
2. **`activate` is the no-op default.** Fixed by
   `willow_mcp.activation.build_activate` — a real, surface-only handler.
3. **The only live daemon runs the seal watch alone.** Fixed by
   `willow_mcp.seat_daemon.build_full_seat_daemon` / `main()` — one
   `SeatDaemon` per seat, running the Grove bus poll, the seal-ledger watch,
   and the heartbeat together.

## The rail, end to end

```
dispatch_send(from_app, to_app, ...)
    │
    ├─ writes dispatch/<ID>/{meta.json,assignment.md,status.json}   (canonical)
    ├─ _pg_mirror_upsert(meta)          best-effort fleet visibility
    └─ _post_dispatch_wake(meta)        best-effort Grove wake  ── NEW
            │
            ▼
    grove_tools.post_wake_envelope(from_app, to_app, dispatch_id, summary, reply_to)
            │  builds a ratatosk Intent.WAKE Envelope (to=to_app, from=from_app's
            │  resolved grove_sender, prompt=summary, reply_channel=reply_to's
            │  channel, extra={"dispatch_id": ...}, a fresh nonce + expiry from
            │  build_envelope)
            │  posts it as a Grove bus message (bus_type=COMMAND) on the
            │  channel named after to_app — the seat's own dedicated
            │  channel, the same convention grove_tools/grove_listen already
            │  use for a seat's inbox (`#<agent>`)
            ▼
   [ Grove: grove.messages row on channel #<to_app>, to_agent=to_app ]
            │
            │  polled by to_app's own SeatDaemon (willow_mcp.seat_daemon,
            │  node=channel=to_app), on its next poll_interval tick
            ▼
    ratatosk.listener.BusListener.run_once
       -> fetch_messages (via grove_tools.build_mcp_call's in-process shim)
       -> parse_grove_message -> validate_envelope   (accepts — see below)
       -> _handle_wake(env) -> self.activate(env)
            │
            ▼
    willow_mcp.activation.build_activate("hanuman")(env)   ── NEW
       appends one `[WAKE] #<channel> trace=<id> <from> -> <to>
       dispatch=<id>: <prompt preview>` line to
       $WILLOW_HOME/logs/grove-listen-<to_app>.log
       — the exact file willow_mcp.grove_listen already writes and
       skills/session-start.md already documents a Claude Code session
       tailing with Monitor.
            │
            ▼
    A session already watching that log (or one that starts watching it)
    NOTICES the wake. Nothing more happens automatically.
```

In parallel, on the same `SeatDaemon.run_forever` cadence, the seal-ledger
watch (folded in via `seal_daemon.build_seal_daemon`, reused unchanged) and
the Grove heartbeat keep running — this is the same `JsonlTailWatcher` /
heartbeat scheduling `seal_daemon.run_seal_watch_forever` already used,
just no longer running *alone*.

## Why `BusListener.validate_envelope` accepts this envelope

`ratatosk.protocol.envelope.validate_envelope` checks, in order:
`v == PROTOCOL_VERSION`, a non-empty `prompt`, `to` matching the listening
node (case-insensitively) or `__all__`, an unexpired `expires_at`, a
`requires_confirm` flag present when the intent is HIGH_RISK (`run_task`,
`shell` — `wake` is deliberately excluded from `HIGH_RISK_INTENTS`, by
design: gating WAKE behind a human confirmation would mean no seat could
ever wake unattended), and nonce-based replay protection.

`post_wake_envelope` builds the envelope with `ratatosk.protocol.envelope
.build_envelope`, which:

- always sets `v=PROTOCOL_VERSION`;
- takes `prompt=` from the dispatch's `summary` (falling back to a fixed
  string when empty — never blank);
- sets `to=to_app`, matching the receiving `SeatDaemon`'s own `node`
  (`willow_mcp.seat_daemon.build_full_seat_daemon` constructs the daemon
  with `node=app_id`, so the two are the same string by construction);
- mints a fresh `nonce` via `secrets.token_hex(8)` and a `trace_id`
  (defaulted to `tr-<dispatch_id lowercased>` when the caller does not
  supply one) — every dispatch has a distinct `dispatch_id`, so nonces and
  trace ids never collide across packets;
- sets `expires_at` to `now + DEFAULT_TTL_SECONDS` (5 minutes) — comfortably
  longer than any real poll interval;
- leaves `requires_confirm` at its computed default, which is `False` for
  `wake` (not a `HIGH_RISK_INTENT`, and `Capability.WAKE` is not a
  `HIGH_RISK_CAPABILITY`), so `validate_envelope`'s confirmation check never
  fires for it.

The one property `post_wake_envelope` does NOT itself guarantee — and does
not need to, because it is the poster, not the receiver — is that the
*next* wake for the same `to_app` arrives with a *different* nonce; that
falls out of `build_envelope` minting a fresh one on every call.

## `activate`'s log line format

One line per wake, appended to
`$WILLOW_HOME/logs/grove-listen-<app_id>.log` (identical path
`grove_listen.default_log_path` resolves to):

```
[WAKE] #<reply_channel> trace=<trace_id> <from_agent> -> <app_id> dispatch=<dispatch_id>: <prompt preview>
```

This mirrors the bracket-tag / `#channel` / arrow shape
`grove_listen.classify` already produces for a bus-addressed message
(`[BUS:COMMAND] #dispatch id=44 willow -> vishwakarma: ...`), documented in
`skills/session-start.md`'s mention table. It is a new tag (`[WAKE]`, not
one of the four existing tags), because a WAKE reaches `activate` through
ratatosk's `BusListener` after `grove_tools.post_wake_envelope` already
posted it — not through `grove_listen`'s own independent LISTEN/NOTIFY
drain of that same Postgres row — so there is no real `grove.messages` row
id available to print as `id=<id>`; `trace=<trace_id>` is the identifier
that is actually available and that ties the line back to the dispatch
packet (`dispatch=<dispatch_id>` is appended when the envelope carries
one). A Monitor tailing this file does not need to recognize the tag in
advance — it notices any new line — so this is additive, not a breaking
change to the four documented tags.

## The in-process `mcp_call` shim

`ratatosk.listener.BusListener` and `ratatosk.daemon.SeatDaemon` are
written against an `mcp_call(tool_name, params) -> result` transport that
normally means a real MCP round-trip to a *separate* willow-mcp server
process (the shape `ratatosk.mcp_client.call` produces — a JSON string, or
occasionally a dict). `willow_mcp.seat_daemon` runs the `SeatDaemon` INSIDE
willow-mcp's own process, so there is no second transport to round-trip
through. `grove_tools.build_mcp_call(app_id)` answers the exact four tool
calls `BusListener`/`SeatDaemon` actually make —
`grove_get_history` (`fetch_messages`), `grove_heartbeat`
(`emit_heartbeat`), `grove_send_message` (the reply post in
`process_message`), and `grove_ack` (`run_once`'s post-dispatch ack) — by
calling straight through to the same `grove.py` functions and the same
manifest-gate checks (`_gate_denied`, `_resolve_sender_checked`) the
registered MCP tools in `grove_tools.register()` use, for one fixed
`app_id` baked in at build time. `params["app_id"]`, if a caller sets it,
is ignored: the shim always acts as the seat it was built for, never
whatever a message payload claims — the same posture every real Grove tool
already has (identity comes from the manifest-checked caller, never from
request data).

### Reconciling the seat's own node identity as sender — and why it must be `app_id`, not the persona

ratatosk's `BusListener` posts its own wake-ack (`process_message`) and
heartbeat (`emit_heartbeat`) with `sender=self.node`/`agent=self.node` — the
seat's RAW node name, which `seat_daemon.build_full_seat_daemon` sets to
the bare `app_id`. `_resolve_sender_checked`'s "post as yourself, no
`grove_relay` needed" free pass — used by the registered MCP tools a REAL
live agent session calls — only recognizes a sender that already equals
the caller's RESOLVED `grove_sender` display name. For any seat whose
specialist registry maps `app_id` to a *different* persona name — the
normal case for every persona-named seat the fleet actually runs — a raw
`sender=app_id` looked, to `_resolve_sender_checked`, like a request to
post as a genuinely different identity, and tripped the sender lock: the
seat's own acknowledgement of its own wake came back `sender_forbidden`.

**First attempt (superseded): resolve the shim's self-posts to the
persona.** The first fix normalized a self-referential `sender` (equal to
`app_id`) to the caller's resolved persona name instead of refusing it.
This closed the `sender_forbidden` bug, but a cross-model audit caught what
it opened: once the persona-named reply landed on the bus, it no longer
matched `node` (still the raw `app_id`), so ratatosk's
`BusListener.is_own_post` — which compares a fetched message's stored
`sender` against `self.node` — **stopped recognizing the seat's own post**.
Nonce-based replay detection cannot catch a self-authored reply either
(`parse_grove_message` mints a fresh nonce on every parse of raw content,
by design, per its own docstring), so `is_own_post` is the ONLY thing
standing between a seat and re-processing its own traffic forever. A
non-WAKE (chat) envelope landing on the seat's own channel would get
answered, its reply (now under the persona name) would look like fresh
inbound on the next poll, and — in the sub-case where that reply's own
`reply_channel` routes back to the same channel — loop indefinitely: a
"seat never acts on its own post" violation the WAKE rail itself never hit
(a WAKE's `activate` always returns a fixed, non-envelope trace string, and
a wake-ack's `reply_channel` is the DISPATCHER's channel, not the seat's
own), but that any ordinary chat envelope handled by the same
`BusListener` could trigger.

**Actual fix: the shim's own automated posts stay under `app_id`, matching
`node` — never the persona.** `grove_tools._shim_resolve_sender(app_id,
raw_sender)`, called from both the `grove_heartbeat` and
`grove_send_message` branches of `build_mcp_call`, replaces the
`_resolve_sender_checked` call those branches used to make: a sender that
is empty or already equals `app_id` (case-insensitively) resolves to
`app_id` itself — not to `resolve_grove_sender(app_id)` — with no
`grove_relay` check needed (posting as yourself is always free). A
genuinely different sender still requires `grove_relay`, exactly like
`_resolve_sender_checked`, and — unlike the self case — is passed through
UNRESOLVED, since relaying on someone else's behalf is not this shim's
identity to rename. This closes BOTH bugs with one rule: the shim's
automated `sender` and `SeatDaemon`'s `node` are now the SAME string
(`app_id`) by construction, so `is_own_post` recognizes the seat's own
traffic again, and posting as yourself is still never refused.

The cost of this fix is cosmetic, not functional: this daemon's own
automated bus chatter (heartbeat, wake-ack, any chat reply the default
`BusListener` handlers produce) now displays under the seat's raw `app_id`
rather than its friendly persona name. A REAL, live human/agent MCP
session's own tool calls are UNCHANGED — `grove_send_message`/
`grove_heartbeat`'s registered implementations still resolve through
`_resolve_sender_checked`/`resolve_grove_sender` exactly as before; only
this shim's own automated identity resolution changed. The alternative —
making `node` itself the resolved persona, so addressing and `is_own_post`
would agree on the "friendly" name — was tried and rejected: `node` is also
what a WAKE's `to` field and ratatosk's plain `"app_id: message"` chat
addressing resolve against, and changing it would have required rewriting
those addressing conventions (and `post_wake_envelope`'s own `to=`
resolution) to match, a far larger and riskier change than reconciling one
shim's sender choice.

## At-least-once / idempotency inheritance

Everything the seal watch already guaranteed still holds, unchanged,
because `willow_mcp.seat_daemon.build_full_seat_daemon` delegates the seal
wiring to `seal_daemon.build_seal_daemon` verbatim rather than
reimplementing it: `ratatosk.daemon.JsonlTailWatcher` persists its offset
**per record**, immediately after that record's callback returns
successfully — not once per batch — so a crash mid-batch resumes exactly
after the last successfully processed record, replaying at most the one
record whose callback was still running (or had just returned) when the
process died. `seal_handler.on_seal` is written to be idempotent for
exactly this reason; nothing here changes that contract.

The Grove bus side inherits the SAME posture, not a different one:
`BusListener.run_once` advances the `ListenerState.cursor` to a message's
id *before* processing it (`self.state.cursor = max(self.state.cursor,
msg_id)`), then calls `process_message`. A crash between the cursor
advance and the `activate` call means that message is not retried — a
missed wake, not a duplicate one — because the cursor was already moved.
Conversely, a crash *before* the cursor advance (e.g. mid-`fetch_messages`)
means the same message is fetched again on restart and re-delivered to
`activate`. Either way, `activation.build_activate`'s handler is
idempotent by construction: appending a second `[WAKE]` line for a
re-delivered envelope is harmless — a human or Monitor sees one extra
notice line, never a spawned duplicate of anything, because this slice
spawns nothing at all. `dispatch_id`/`trace_id` on the line make a
duplicate visually identifiable if it ever needs to be discounted.

`post_wake_envelope` itself is called once per `dispatch_send`, is
best-effort (a failure is swallowed, never retried automatically), and
carries no delivery guarantee beyond "posted, or didn't" — a dispatch whose
wake failed to post is still fully valid and discoverable by polling
(`dispatch_list`), exactly as it was before this slice existed. The wake is
convenience, not the source of truth; the filesystem packet is and remains
canonical.

## Deploy correctness: the DB name and the manifest

The daemon's only path to Grove is `grove_tools.build_mcp_call`, which goes
through `willow_mcp.db.get_pg()` — a Unix-socket connection keyed on
`dbname=paths.pg_db()` (`WILLOW_PG_DB`, default `"willow"`) and
`user=WILLOW_PG_USER`. **There is no DSN-url reader anywhere on this path.**
`WILLOW_DB_URL` is read exclusively by `grove_listen.py`'s own separate,
dedicated LISTEN connection — a different code path this daemon never
touches — so setting it in the daemon's unit environment does nothing at
all. Grove's own tables live in the fleet's `willow_20` database, not
willow-mcp's default `willow` (see `grove.py`'s own "DB-name trap"
docstring); the deploy template
(`deploy/willow-seat-daemon.service.template`) sets
`WILLOW_PG_DB=willow_20` explicitly for this reason. Getting this wrong is
dangerously quiet: the daemon still starts, still heartbeats (a heartbeat
post degrading to `postgres_unavailable`/`grove_unavailable` is logged and
swallowed, same best-effort posture as everything else on this rail), and
every `grove_get_history` poll comes back empty — the seat looks alive and
sees and posts zero wakes, indistinguishable from a genuinely idle bus
without checking the logs.

Separately, `{{APP_ID}}`'s manifest needs BOTH `grove_read` AND
`grove_write` in its `permissions` — not just one. `grove_read` alone lets
`grove_get_history` succeed but denies every `grove_heartbeat`/
`grove_send_message`/`grove_ack` call the bus needs to post, so a WAKE is
fetched but its ack, and the seat's own presence heartbeat, are silently
refused. `grove_write` alone means `grove_get_history` itself is denied, so
no WAKE is ever fetched at all. Either gap alone still looks like a running
daemon (no crash, a clean heartbeat attempt) while the wake -> activate
loop never actually closes.

## Deferred: auto-spawning the seat runtime

This slice is explicitly **surface-only**: a wake makes a seat *notice* —
it appends a log line that a session watching it can read — it does **not**
spawn a new process, start a new Claude Code session, or launch an agent.
The natural next step — a WAKE causing an actual seat runtime to come up
unattended (e.g. `activate` shelling out to start a Claude Code session
bound to the dispatch, or handing the packet to a supervisor that manages
seat processes) — is a deliberate fork left OUT OF SCOPE here, ratified by
the operator as a separate, later decision. Nothing in this slice's
plumbing forecloses it: `build_activate`'s `activate` callable is a single
swappable function; a future slice can build a different one (or wrap this
one) that does more than log, without touching `post_wake_envelope`,
`build_mcp_call`, or `seat_daemon`'s bus/seal wiring at all.

## Files

- `src/willow_mcp/dispatch.py` — `_post_dispatch_wake` (best-effort wake
  post, called from `dispatch_send` after `_pg_mirror_upsert`).
- `src/willow_mcp/grove_tools.py` — `post_wake_envelope` (builds + posts
  the WAKE envelope) and `build_mcp_call` (the in-process shim).
- `src/willow_mcp/activation.py` — `build_activate` (the real,
  surface-only wake handler).
- `src/willow_mcp/seat_daemon.py` — `build_full_seat_daemon` / `main()`
  (the full per-seat daemon: bus + seal watch + activate).
- `src/willow_mcp/deploy/willow-seat-daemon.service.template` — systemd
  `--user` template unit, generalized on `app_id` (`%i`), sibling to the
  existing `willow-seal-watch.service.template` (which remains the
  seal-only, no-bus deployment path and is unchanged).
- `tests/test_activation_rail.py` — coverage for all four pieces above.
