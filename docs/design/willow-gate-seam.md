---
kind: doc
name: willow-gate-willow-mcp-the-seam
description: "Maps how willow-gate's agent-side HMAC binder composes with willow-mcp's existing authorization stack — identity, tier-vs-permission-groups, enforcement, session lifecycle, audit, and friction_floor — before the invasive wiring is built."
---

@markdownai v1.0

# willow-gate ↔ willow-mcp: the seam

Status: **proposal / mapping only** (no code yet). This pins how
[`willow-gate`](https://github.com/willow-memory/willow-gate) composes with
willow-mcp's existing authorization stack *before* any of the invasive wiring is
written, so we can prototype one slice at a time without guessing the shape.

## The gap it fills

willow-mcp's entire ACL — `gate.permitted(app_id, tool)`, the sudo invariant,
`store_scope` confinement — trusts that the **`app_id` argument is honest**. In
stdio/agent mode it is just a string passed on every tool call. There is already
an identity binder for *humans* — `identity_binding.py` maps a verified OAuth
`(issuer, subject)` to an `app_id` in serve mode, confirmed only via the local
`willow-mcp confirm-binding` CLI — but **agents don't OAuth**, so the agent path
has no binding at all.

willow-gate is the missing **agent-side** binder: an HMAC over a 13-field header,
keyed by a per-agent secret the gate holds, with the claimed `trust_level` capped
at a registered ceiling. *"Elder is not a text field anyone can type."* It does
not replace `identity_binding.py`; it sits beside it, and both feed the same
resolution point.

## The two systems at a glance

| Concern | willow-mcp today | willow-gate | Seam |
|---|---|---|---|
| Human identity | OAuth → `identity_binding.resolve_app_id` (serve mode), CLI-confirmed | — | keep |
| Agent identity | `app_id` string, **unbound** | HMAC-signed header, secret held by gate, trust capped at registered ceiling | **new binder** |
| Authorization | `PERMISSION_GROUPS` per manifest (fine-grained tool sets), fail-closed, `deny_tools` | trust ladder 0–4 → coarse classes {read, write, query, execute, admin} + export gate | **tier as ceiling over groups** |
| Enforcement | `_guarded` → `_gate` → `permitted` → receipt; PreToolUse tripwire | `authorize_tool(session, tool, export=)` (hook) / `bind_tools` (in-proc) | `authorize_tool` **inside `_gate`** |
| Session | `session_enter` / `session_handoff_write` | `check_in` / `check_out` with 13-field declare-vs-did diff | check_in ↔ session_enter |
| Audit | `ReceiptLog` | PGP-encrypted ledger + graduated announcement volume | receipts carry tier/announce policy |
| Relationship drift | *(nothing)* | `friction_floor` — model-free sycophancy smoke detector | **orthogonal**, separate wiring |

## Layer-by-layer seam

@phase 1-identity-two-binders-one-resolution-point
### 1. Identity — two binders, one resolution point
- **Humans / serve mode:** unchanged — `identity_binding` maps OAuth `(issuer,
  subject) → app_id`, CLI-confirmed.
- **Agents / stdio+dispatch:** willow-gate `register_agent(agent_id, secret,
  max_trust)` (operator-side, like `confirm-binding` is CLI-only) provisions a
  per-agent secret + trust ceiling. `check_in(header)` HMAC-verifies the caller
  and yields a bound session carrying `agent_id` + verified `trust_level`.
- `_gate` becomes the single resolver: it accepts **either** a confirmed OAuth
  binding **or** a valid willow-gate session, and produces `(bound_app_id,
  trust_level)`. An authenticated-but-unbound / signature-invalid caller is
  denied — same fail-closed rule `identity_binding` already uses.
- **Opt-in per deployment.** HMAC binding must not be forced on a local
  single-operator box (no ceremony wanted there). Rule: if an `app_id` is
  *registered with a secret*, its calls **must** be signed; unregistered local
  app_ids fall back to today's manifest-only, trusted-host behavior. Same shape
  as `WILLOW_VAULT_RESTORE` being opt-in.

@phase 2-trust-tier-vs-permission-groups-tier-is-a-ceiling-not-a-replacement
### 2. Trust tier vs permission groups — tier is a *ceiling*, not a replacement
willow-gate's `allowed_tools` are **coarse classes** (`read, write, query,
execute, admin`); willow-mcp's `PERMISSION_GROUPS` are **fine-grained**
(`store_read`, `knowledge_write`, `task_queue`, `full_access`, …). Do **not**
collapse one into the other. Compose them:

```
effective_tools = expand(manifest.permissions)     # what this app may hold
                  ∩ tier_ceiling(trust_level)       # what this tier may hold
gated further by:
  - read_only / write_export_allowed  → write & export tools
  - announcement_volume + audit_level → receipt loudness (§5)
```

A first-cut class→group map (to be refined):

| willow-gate class | willow-mcp groups it unlocks |
|---|---|
| read | `store_read`, `knowledge_read`, `gap_read`, `dispatch_read`, `fleet_read`, `audit`, `lineage_read` |
| write | `store_write`, `knowledge_write`, `gap_write`, `context`, `lineage_write` |
| query | search-heavy reads (`store_search_all`, …) |
| execute | `task_queue`, and — export-gated — `integration_call` / `task_net` |
| admin | `schema_admin`, `gap_purge`, manifest/registry ops |

Note the natural alignment: willow-gate's **export gate** ↔ willow-mcp's
egress lines (`integration_call` / `task_net`) that are *deliberately excluded
from `full_access`* and granted on their own line. Export tools stay export-only
at every tier below `write_export_allowed`.

@phase 3-enforcement-seam-authorize-tool-inside-gate
### 3. Enforcement seam — `authorize_tool` inside `_gate`
`_gate` is already the "authorize before dispatch, then receipt" point.
willow-gate's `authorize_tool(session, tool, export=)` slots **inside** it: after
`permitted()` says the manifest allows the tool, `authorize_tool` applies the
tier ceiling, export gate, drift/fail budgets, and announcement. The PreToolUse
hook remains the *external* mirror of the same check (defense-in-depth).
`bind_tools`/`GatedSession` is **N/A for the MCP surface** — MCP tools are
framework-dispatched, not a passed callable list — so the funnel is
`authorize_tool`-in-`_gate`, never `bind_tools`.

@phase 4-session-lifecycle-reconciliation-on-top-of-session-enter-handoff
### 4. Session lifecycle — reconciliation on top of session_enter/handoff
- `check_in` ↔ `session_enter`: `session_enter` performs the willow-gate check-in
  (HMAC-verify, establish the bound tiered session subsequent `_gate` calls
  consult). Its existing `entry_mode`/assignment return is unchanged.
- `check_out` (13-field **declare-vs-did diff**) ↔ `session_handoff_write`: what
  the agent declared on entry (`tools`, `pass_count`, `fail_count`, `drift`,
  `state_hash`) is reconciled against what it actually did — and because only
  authorized calls are recorded, that reconciliation is true for free.
- Defining willow-mcp's 13-field entry/exit declaration is its own schema task;
  can be a later phase.

@phase 5-audit-receipts-gain-tier-announcement-policy
### 5. Audit — receipts gain tier + announcement policy
Keep `ReceiptLog` as the record of every gated call; layer willow-gate's
**graduated announcement volume** (louder for the *less* trusted) and
`audit_level` (`full` vs `minimal`) as a policy over it, and optionally its
PGP-encrypted ledger for the announcement channel. Receipts already log every
`_gate` decision — this adds *how loudly*, not a second log. **SHIPPED —
`announce.py`; the volume/`audit_level` policy is pure stdlib and the encrypted
ledger is a pluggable `set_sink()`, so the base never imports python-gnupg (D5).**

@phase 6-friction-floor-orthogonal-not-part-of-the-gate-seam
### 6. friction_floor — orthogonal, not part of the gate seam
`friction_floor` watches the agent→**user relationship** (sycophantic mirroring
during a user escalation), not access. It runs *outside* the model it watches,
flags loud for a human, never blocks. It wires to session **transcripts**, not
`_gate` — a separate monitor. In scope for "bring in willow-gate," out of scope
for the authorization seam. (Cleanest standalone slice to prototype first if we
want a quick, low-risk win.)

## Invariants that must survive the merge
1. **Sudo invariant.** `admin`/Elder trust is *not* sudo. Authority (minting
   manifests, secrets, trust ceilings) stays CLI/operator-side —
   `register_agent` is operator-only, matching `confirm-binding`. No MCP tool
   may raise its own tier or write its own secret.
2. **Fail-closed everywhere.** Invalid signature, unknown agent, unbound caller,
   tier-below-tool → deny, same as an unmanifested `app_id` today.
3. **Agent-neutral base stays usable locally.** Binding is opt-in; a plain local
   clone keeps working with manifest-only auth and no HMAC ceremony.
4. **Secrets are never MCP-writable.** Per-agent secrets live in the keystore
   **outside** `mcp_apps/` — `$WILLOW_HOME/gate/secrets/<agent_id>.key` (`0600`)
   with the ceiling registry at `$WILLOW_HOME/gate/registry.json` — so no
   store/list tool can even enumerate them (D2). They are provisioned by the
   operator (`register-agent`/`rotate-agent`), never reachable from a tool, and
   the `gate/` path is on the PreToolUse guard's owned-marker side (`_KEYSTORE_RE`)
   so a Bash/Write path that tries to mint or rotate a secret is blocked too.
5. **The two ledgers stay distinct.** willow-gate's ledger is a *custody* story
   (who did what, at what trust); `lineage` is a *decision* story (why things
   are). Complementary, not merged.

## Holes found (spike)

A runnable spike composed the *intended* bridge above and attacked it. willow-gate's
crypto core held through the bridge — trust-ceiling cap, forged signature, nonce
replay, and the `reserved` trap were all rejected — and the intended composition
closed the obvious over-grants (a read-only-manifest agent could **not** write by
passing `app_id=operator`; egress needed *both* manifest and tier). Two "holes"
the spike shows are really *build-it-right constraints*: a bridge that trusts the
`app_id` argument, or leans on the tier without the manifest ∩, over-grants — the
intended bridge already denies both. Three genuine holes remain for the full
build, plus one policy call and one upstream bug:

- **H1 — session↔app_id binding is the whole ballgame (BLOCKER).** Every
  willow-mcp tool takes `app_id` as a plaintext string. The HMAC binds a
  *session*, but nothing ties a given MCP call to that session — a caller passing
  `app_id=operator` rides operator's live session with no auth of its own. **The
  full build must carry a per-call credential on every gated call; `app_id` alone
  cannot bind.** Largest change; touches every tool signature. *Prototyped — see
  "H1 prototype" below: a per-call HMAC signature (SIGNED) is the fix; a bearer
  session token closes the ride but not replay.*
- **H2 — willow-gate must BE `_gate`, not sit beside it.** `_gate` today
  authorizes via `permitted()` alone. Unless `authorize_tool` runs *inside*
  `_gate` as the sole funnel, willow-gate is a ledger, not a gate: a call that
  reaches a tool any other way is neither prevented nor recorded. *Prototyped —
  the funnel already exists (see "H2/H3 prototype"): `@_guarded` is the sole
  wrapper on every tool, `_gate` already returns an `effective_app_id` distinct
  from the raw arg, so H2 is inserting willow-gate's authorize at that existing
  point, not building a funnel.*
- **H3 — reconciliation needs a real `tools_used` feed.** `check_out`'s
  declare-vs-did diff only sees tools that passed through `authorize_tool`. It
  must be fed from `ReceiptLog`, or reconciliation silently passes on out-of-band
  use. *Prototyped — `ReceiptLog` already records every `ok`/`denied` decision at
  the funnel; sourcing `tools_used` from `ReceiptLog.tail` reconciles correctly
  AND flags an exit that claims a tool no receipt ever authorized.*
- **Policy — read-universal does NOT survive the seam.** willow-gate grants read
  by *construction*, not by tier: `check_in` unions `{READ_TOOL}` into whatever
  the header declares and `authorize_tool` short-circuits it, so a level whose
  `allowed_tools` is empty still reads. willow-mcp fail-closes an
  unmanifested/unscoped `app_id`, and in the bridge that WINS. Bringing in
  willow-gate does **not** make willow-mcp reads universal — `store_scope` still
  confines. State it; don't inherit it by accident.
  **Written upstream (2026-08-10):** willow-gate's README now carries the policy
  and the `host_acl ∩ tier_ceiling` composition rule, citing this seam as the
  worked example. The spike's "*even Exiled*" phrasing was imprecise — see the
  next bullet.
- ~~**Upstream bug — `entry_allowed` unenforced in willow-gate.**~~ **Fixed
  upstream (willow-gate#12).** Level 0 is `entry_allowed=False` and `check_in`
  now refuses it (`willow_gate/__init__.py:280`), with test coverage. Note this
  also corrects the bullet above: Exiled's `allowed_tools` is `()` *and* it
  cannot open a session, so read-universal means universal among agents who may
  **enter** — not universal full stop.

## H1 prototype — how a call binds to a session (resolved)

A second spike prototyped the missing binder — what each call carries *besides*
`app_id` — across three modes, attacking each with ride / replay / tamper:

| mode | what the call carries | ride | replay | tamper |
|---|---|---|---|---|
| APPID_ONLY (today) | `app_id` only | **HOLE** | — | — |
| BEARER | + a session token minted at check-in | closed | **HOLE** (token reusable for any later call) | HOLE |
| SIGNED | + `(session_id, call_nonce, HMAC(secret, session_id\|app_id\|tool\|call_nonce))` | closed | closed (nonce single-use) | closed (sig binds app_id+tool) |

**Decision: SIGNED per-call HMAC.** It is the only mode that closes all three —
it extends check-in's exact HMAC model to every call. Bearer stops the ride (a
real gain over today) but a captured token replays for any call for the session's
lifetime, so it is acceptable *only* where the transport itself is the trust
boundary.

Practical shape (**SHIPPED** — client: `willow_mcp/signing.py`; server:
`_read_call_credential` / `_current_call_credential` in `server.py`):
- **The MCP client signs, not the LLM.** The harness wrapping the agent holds the
  per-agent secret and signs each call; the model never sees the secret and
  cannot fabricate or omit a signature. This is client-side signing middleware —
  a real integration cost, and the point: an un-instrumented client cannot call
  gated tools. `ClientSigner(agent_id, secret, session_id).meta_for(tool)` is that
  middleware; `signed_call_tool(session, signer, name, args)` is the one-liner.
- **The credential rides out-of-band** in the MCP request's `_meta` (key
  `willow_call_credential`), *not* as a tool parameter — tool schemas stay clean and
  the model can't touch it. `_gate` reads it from the request context
  (`mcp...request_ctx` → `.meta.model_extra`), never from `arguments`.
- `_gate` becomes: read `(session_id, call_nonce, sig)` → resolve to `(agent_id,
  trust)` → **require `agent_id == app_id`** → then today's `permitted()` + tier.
- **Mode by deployment:** SIGNED is required for serve-mode / multi-agent. For a
  single-agent stdio deployment where the private pipe already authenticates the
  peer, BEARER (or a session handle) is an acceptable lighter choice.

Residual limits to carry into the build: per-agent secret provisioning (D2); a
per-session used-nonce set that is dropped at check-out (bounded growth); and the
hard truth that any client not instrumented to sign simply cannot reach a gated
tool.

## H2/H3 prototype — the funnel already exists (resolved)

Reading `_guarded`/`_gate` changed H2/H3 from "build" to "insert":

- `@_guarded` wraps **every** `@mcp.tool` — the sole funnel is already structural;
  the raw tool body has no un-gated handle.
- `_gate` already returns an `effective_app_id` distinct from the caller-supplied
  `app_id` (built for serve-mode OAuth binding) — the exact point the H1 SIGNED
  binder + `authorize_tool` slot into.
- `_guarded` already receipts every decision (`ok` / `denied` / `rate_limited` /
  `error`) via `ReceiptLog`.

A prototype composed `_gate_v2 = SIGNED binder → authorize_tool → permitted()`
behind a `@guarded` wrapper over the **real** `ReceiptLog`, and showed:
- an authorized call runs its body; a denied call's body **never** runs;
- `check_out` reconciliation sourced from `ReceiptLog.tail` matches what actually
  ran, and **flags** an exit that declares a tool no receipt authorized
  (out-of-band claim caught).

So H2 = swap the `app_id`-verbatim step in `_gate` for `_gate_v2`; H3 = compute
`tools_used` from `ReceiptLog` at `check_out`. Neither needs new plumbing.

## D1 — tier ↔ permission-group map (settled)

willow-gate's tiers unlock **classes** cumulatively (Rookie=`read`; Steady
=`read,write`; Veteran=`+query,execute`; Elder=`+admin`); each class maps to a
set of willow-mcp permission **groups**. Effective authorization is:

```
effective = expand(manifest.permissions) ∩ groups(tier_classes) ,
            with write-class stripped when the tier is read_only,
            and egress requiring BOTH the export axis AND the manifest own-line.
```

| class | tier ≥ | willow-mcp groups it unlocks |
|---|---|---|
| **read** | Rookie(1) | `store_read`, `knowledge_read`, `gap_read`, `dispatch_read`, `fleet_read`, `integration_read`, `audit`, `lineage_read`, and `session_enter` / `context_get` / `context_list` |
| **query** | Veteran(3) | **≡ read today** — reserved. willow-mcp has no capability that is "query but not read" (`store_scope` already confines breadth), so `query` unlocks nothing extra *yet*. If a genuinely broad/expensive discovery tool is added, it moves to a `query`-only group; until then Veteran's real gain is `execute`. |
| **write** | Steady(2) | `store_write`, `knowledge_write`, `gap_write`, `dispatch_write`, `lineage_write`, and `context_save` / `context_expire` |
| **execute** | Veteran(3) | `task_queue`, `agent_dispatch` (`agent_route` / `agent_dispatch_result`); **export-gated** `integration_call` / `task_net` (still require the manifest's own-line grant) |
| **admin** | Elder(4) | `schema_admin`, `gap_purge`, `gap_promote` |

Ratified edge calls:
- **Egress stays double-gated.** `integration_call` / `task_net` are unlocked by
  `execute` **only when** the tier's `write_export_allowed` is true **and** the
  manifest grants them on their own line. Even Elder cannot egress without the
  manifest grant — the existing own-line invariant is preserved, not softened.
- **`admin` ≠ sudo.** The `admin` class reaches `schema_admin` / `gap_purge` /
  `gap_promote`, **never** authority: minting manifests, secrets, or trust
  ceilings stays CLI/operator-only and is not a tool at any tier.
- **`store_purge_collection` stays `write`-class**, not elevated to `admin`: it
  is reversible (archive-don't-delete) and already confirm-guarded, so Steady may
  use it — matching today's ACL. Only genuinely irreversible/rule-changing verbs
  are `admin`.
- **Reads fail-closed, not universal.** Per the policy call above, an
  unmanifested/unscoped `app_id` is denied even for `read` — willow-gate's
  "read-universal" does not survive the seam; `store_scope` confines.
- **Tier caps `full_access`.** A `full_access` manifest at Steady tier can still
  only reach `read`+`write` groups — the intersection is the point.

## D2 — secret store, rotation, and CLI (settled)

**Layout.** Per-agent secrets live operator-side, in a dedicated keystore
**outside** `mcp_apps/` so no store/list tool can even enumerate them:

```
$WILLOW_HOME/gate/registry.json          # {agent_id: {max_trust}}  — auditable, no secrets
$WILLOW_HOME/gate/secrets/<agent_id>.key # 32 random bytes, 0600, atomic write (os.replace)
```

This **splits** willow-gate's default (which bundles `secret.hex()` + `max_trust`
in one `registry.json`): the ceiling registry stays readable/auditable while
secret material sits in per-agent `0600` files. The whole `gate/` dir is
`0700`, operator-owned, and added to the PreToolUse guard's owned markers so no
Bash/tool path may read or write it — it is a keystore, guarded like one.
(Upstream nicety to file: have willow-gate `0600` its own `registry.json`.)

**Provisioning is symmetric and two-sided.** The same secret is held by the gate
(to verify) and by the MCP **client's** signing middleware (to sign, per H1). The
CLI generates it; the operator installs the printed key into the client config
out-of-band. Asymmetric (client signs with a private key, registry holds only the
public key — no shared secret) is the stronger end-state but needs willow-gate's
`signature` field widened beyond 64 hex; **filed as a future hardening, symmetric
for v1** to match willow-gate as-is.

**Rotation.** `rotate-agent` writes a new `<agent_id>.key`. Rotation is **hard by
default**: sessions signed with the old secret fail their next `authorize_tool`
(signature mismatch) and must re-check-in — correct behaviour for a
compromise-response. An optional grace window (registry holds `{current, previous,
expires}`, both accepted until expiry) is a willow-gate enhancement to file if
zero-downtime rotation is wanted; a key-version stamped into each ledger entry
records which key signed.

**CLI, never a tool** (same constraint as `confirm-binding` — stdio-only, host
that owns `$WILLOW_HOME`):
- `willow-mcp register-agent <agent_id> --max-trust N [--generate | --secret-file P]`
  — **requires an existing manifest** for `<agent_id>` (identity and ACL are
  provisioned together; the seam ties `agent_id == app_id`), generates a 32-byte
  secret when `--generate`, writes it `0600`, and prints it **once** for the
  operator to install in the client.
- `willow-mcp rotate-agent <agent_id>` / `revoke-agent <agent_id>` for lifecycle.
- All are authority acts — excluded from every permission group and unreachable
  from the MCP surface, upholding the sudo invariant.

## Open decisions (the forks to settle before wiring)
- **D1 — tier↔group map:** **settled — see "D1" above.**
- **D2 — secret store, rotation, CLI:** **settled — see "D2" above.**
- **D3.1 — the third position, `strict` (added 2026-08-27).** D3 settled that
  an unregistered app stays manifest-only, so a plain clone keeps working. Correct
  for adoption, and it leaves one bit carrying two unrelated meanings: "binding is
  not enabled for this deployment" and "this agent is unknown". willow-gate reads
  the same fact the opposite way — an unregistered check-in has no expected
  signature to compare against and is a hard stop
  (`test_checkin_unregistered_agent_rejected`). While the halves disagree, partial
  adoption *inverts* the control: registering the gatekeeper and leaving the
  orchestrator unregistered hardens the lesser identity and leaves the most
  privileged one on the unbound path, because nothing stops a caller passing a
  different `app_id`. `on` closes H1 for agents that opted in, which is a weaker
  claim than closing H1.

  `WILLOW_MCP_ENFORCE_BINDING` now takes three positions — `off` / `on` /
  `strict`. `strict` is `on` plus: an unregistered app_id is DENIED. It is a
  separate position rather than a change to `on` because the rollout needs both:
  register everyone, run `on` and read the `bind_observed` / `bind_enforced`
  receipts, then move to `strict` once `list-agents` covers the roster. An
  unrecognized value now raises rather than reading as off — a typo'd `stict`
  silently meaning "no enforcement" is this section's own failure mode one layer
  up.

- **D3 — stdio default:** **settled — see "D3" above.** Both: an explicit env
  switch (`WILLOW_MCP_ENFORCE_BINDING`) *and* per-agent registration, so an
  operator can register + observe before the switch can deny anything.
- **D4 — declaration schema:** **settled — see "D4" above.** Entry = the 13-field
  check-in header; the reconciled subset is `{tools, pass_count, fail_count, drift,
  state_hash}`, of which only `tools` has receipt-log ground truth.
- **D5 — vendoring:** **settled — vendored/pure, no PGP dep.** Every shipped
  piece (`friction_floor`, `agent_registry`, `session_binder`, `tier_policy`,
  `announce`) is stdlib-only; willow-gate's PGP-encrypted announcement ledger is
  left as a pluggable `announce.set_sink()` an operator can wire, so the base
  never takes on `python-gnupg`. The base stays dependency-free.
- **D6 — `dispatch_write` trust (residual, B-48, issue #236):** Orchestrator
  writes (`dispatch_send` for `app_id=willow`) are human-attested (+ PGP
  session file when enabled). Builder seats with `dispatch_write` are
  manifest-gated only — stdio can inject fleet packets without per-call
  binding. Red-team 2026-07-31 demonstrated live packet creation. Traced
  2026-08-01: `_enforce_binding_gate` already applies uniformly to
  `dispatch_write` when `WILLOW_MCP_ENFORCE_BINDING=1` is on (`_gate` calls
  it for every tool, no `dispatch_write`-specific carve-out) — but it's a
  no-op for any **unregistered** app_id, by design (D3: an un-instrumented
  client must fail closed rather than be silently forced onto a signing
  protocol it never opted into). So this closes today only when the
  operator both flips the switch *and* runs `register-agent` for every
  builder seat — the same two-step deployment gap as #231's uid separation,
  not a code bug. Making `dispatch_write` refuse an unregistered app_id
  unconditionally (skipping the manifest-only fallback) was considered and
  deliberately deferred: it would deny `dispatch_send` on every install that
  hasn't registered its builder agents yet, a breaking default-posture
  change bigger than this one finding warrants on its own.

## A phased path (each phase is independently shippable)
1. **friction_floor watcher** — orthogonal, no auth-path risk; net-new signal.
   Unblocked by every hole below — the safe first slice. **SHIPPED**
   (`friction.py` + vendored `friction_floor.py`).
2. **Session credential + identity binding (read-only)** — add the per-call
   session token (**H1**), `register_agent` + `check_in` HMAC-verify feeding
   `_gate`, *observed only* (log the bound tier, don't enforce). Nothing after
   this works without H1, so it leads. **SHIPPED** (`agent_registry.py`,
   `session_binder.py`, `_observe_binding` in `server.py`).
3. **Tier ceiling enforced** — `authorize_tool` *inside* `_gate` as the sole
   funnel (**H2**), applying §2 once D1 is ratified. **SHIPPED**
   (`tier_policy.py` = the D1 map as a pure tested table; `_enforce_binding_gate`
   inside `_gate`; gated by `WILLOW_MCP_ENFORCE_BINDING`, see D3 below). The
   ceiling is applied *after* `permitted()` — manifest ∩ tier, fail-closed — and
   the single-use nonce is consumed exactly once (enforcement verifies; the
   observe hook steps aside when enforcing).
4. **Session reconciliation** — `check_out` declare-vs-did, with `tools_used` fed
   from `ReceiptLog` (**H3**). **SHIPPED** (`session_binder.reconcile` /
   `check_out`, `ReceiptLog.since`, the `session_reconcile` tool). Runs alongside
   `session_handoff_write`, never blocking it: it RECONCILES and records (receipt
   `reconciled` / `reconcile_discrepancy`), it does not gate the handoff. See D4.
5. **Announcement/ledger policy** — graduated loudness + optional encrypted
   channel over `ReceiptLog`. **SHIPPED** (`announce.py`, the
   `ReceiptLog.on_record` hook, the `announce` gates-panel row). A policy over the
   log, not a second log: it decides how loudly each recorded decision is
   surfaced on the operator channel — graduated by bound tier (louder for the less
   trusted; unbound is loud; Elder's routine calls silent), every denial/
   discrepancy escalated to ALERT. `WILLOW_MCP_ANNOUNCE` gates it (off ⇒ a plain
   box is unchanged and the record path pays nothing); `WILLOW_MCP_AUDIT_LEVEL`
   = `full`|`minimal` sets whether routine trusted activity is surfaced or only the
   loud stuff. The PGP-encrypted ledger stays a pluggable `set_sink()` so it can be
   wired without the base taking on python-gnupg (D5). **The seam's four holes
   (H1/H2/H3 + policy) and D1–D5 are all closed.**

6. **Outbound binding — the federated client signs.** **SHIPPED**
   (`mcp_federation.signing_config` / `load_signing_secret`,
   `_ServerConnection._bind_if_signed` / `_reconcile_if_signed`,
   `tier_policy.classes_for_tier`). Phases 1–5 made this server *enforce* a
   caller's identity; this is the same seam in the other direction — what this
   server presents when it calls someone else.

   A ratified entry may carry `signing_agent_id`, `signing_secret_env`, and
   `signing_trust_level`. When it does, the connection checks in once via
   `session_bind` after `initialize()`, signs every subsequent `call_tool` with a
   per-call credential in `_meta`, and checks out at disconnect declaring the
   classes it actually called (which is what frees the session's single-use nonce
   set downstream — a long-lived link that never checks out grows it for the
   downstream process's life). An entry without `signing_agent_id` is unsigned and
   behaves exactly as before.

   Three properties worth stating, because each is a decision rather than an
   accident:
   - **The identity is attached at `ratify()`, never parsed from a `.mcp.json`.**
     `McpServerSpec` is "a fact about what was on disk at parse time"; a config
     file discovered on disk must not be able to choose which identity this
     server presents. That is the outbound twin of Decision 4(a).
   - **The secret is never stored.** The entry names an environment variable; the
     value is read from this process at connect time, exactly as `load_server_env`
     reads `env_keys`. The registry is world-readable operator config that gets
     PGP detach-signed — it is not a keystore.
   - **Fail-closed throughout.** A missing, malformed, or short secret, or a
     refused check-in, raises rather than connecting unsigned; the config is
     resolved *before* a child process is spawned, so a link that cannot sign
     never starts one. `SigningConfigError` is raised, not returned, so a caller
     cannot mistake "no secret" for "no signing configured".

   **What it buys depends on who you are calling.** Against a downstream this
   process spawns it is least-privilege and audit — the downstream's tier ceiling
   applies to us, its receipt log attributes our calls, and check-out reconciles
   our declaration against its own log — but not *authentication*, because we
   already chose that child's binary and environment. Against a peer this process
   did not start, it is authentication, and Phase 7 makes that peer reachable.

7. **Remote transport — the peer this process did not spawn.** **SHIPPED**
   (`mcp_federation.is_http_transport` / `validate_remote_url` /
   `load_auth_headers`, `_ServerConnection._transport`). An entry with
   `transport: streamable-http` and a `url` is dialled over the network;
   `auth_token_env` optionally names an env var holding a bearer token.

   This is the phase that makes Phase 6 load-bearing rather than ornamental —
   and it is the first time federation reaches something willow-mcp did not
   fork, so it is also the first time the destination itself is attacker-
   influenced. Two properties carry that weight:
   - **The destination is validated at ratification AND at every connect**, via
     `web_fetch.validate_fetch_url` — the open-web lane's guard, which *resolves*
     names rather than pattern-matching them. Validating once at ratification
     would be exactly the "cached decision is a claim" mistake Decision 5 names:
     the registry records a URL, but DNS decides where a name points, and it can
     be re-pointed at loopback or `169.254.169.254` long afterwards without the
     registry changing.
   - **Reusing that guard rather than writing a second one.** A local copy would
     be a weaker duplicate of a control that has already been audited.

   Consequence worth stating because operators will hit it: **a remote downstream
   cannot be on `localhost`.** Loopback, link-local and private space are refused.
   That is the guard working; a local downstream is what `stdio` is for.

   The five egress locks in `federation_egress` are unchanged and apply to a
   remote peer exactly as to a spawned one — this phase changes what is dialled,
   not who may dial it.

### Residuals after the build (known, tracked)
The mechanism is complete and fail-closed. The client signer is now shipped, so
enforcement runs end to end; what remains is one operator step and one pre-existing
gap the review surfaced:
- **The per-call credential is now wired (H1 "practical shape" — SHIPPED).** The
  client rides `{session_id, call_nonce, sig}` in the MCP request's out-of-band
  `_meta` (key `willow_call_credential`); the server reads it via
  `server._read_call_credential()` from the request context and the gate consults it.
  The client half is `willow_mcp/signing.py`: the low-level `build_checkin_header`
  / `ClientSigner` / `signed_call_tool`, plus **`SigningClientSession`** — the real
  harness wrapper over an MCP `ClientSession` that holds the secret, checks in once
  (`.bind`), signs every subsequent call (`.call`), and checks out (`.reconcile`).
  The model driving the session never sees the secret or a signature.
  Flow under enforcement: `session_bind` is the ONE bootstrap call (exempt from the
  per-call credential — there is no session yet, and it authenticates via its own
  header HMAC), it returns the `session_id`, and every subsequent call carries a
  fresh per-call signature in `_meta`. Proven end to end against a REAL stdio server
  by `examples/signing_client.py` (a runnable operator demo) and
  `tests/test_signing_e2e.py` (in-memory transport, real dispatch): a signed call
  passes, an unsigned one is denied, the tier ceiling denies an over-tier tool, and
  check-out reconciles clean.
  The remaining operator step is real provisioning: `register-agent`, install the
  printed secret into the harness's signer config, then flip
  `WILLOW_MCP_ENFORCE_BINDING=1`. An un-instrumented client still cannot reach a
  gated tool (that is the design), so keep enforcement off until every registered
  agent's harness is signing; observe-only stays the safe default.
- **No caller in the current fleet can take that step yet (2026-08-10 survey).**
  The mechanism is complete and proven — `examples/signing_client.py` passes end
  to end — but every live path into this server is either unable to sign or does
  not need to:
  - **IDE seats (Claude Code / Cursor)** cannot emit `_meta.willow_call_credential`
    and never call `session_bind`. Registering one is strictly negative: it adds
    no observability (see below) and arms `WILLOW_MCP_ENFORCE_BINDING=1` to deny
    the operator's own seat.
  - **`willow-mcp worker`** is in-process, not an MCP client.
  - **Serve mode** is already bound via OAuth.
  - **`mcp_federation_client`** ~~does *not* sign~~ — **now signs (2026-08-10).**
    See "Phase 6" below.
- **Registration is not the observe-only lever, and the phase list reads as if it
  were.** `_observe_binding` never consults `is_registered()`: it records a
  receipt when a per-call credential is present, else when `session_for(app_id)`
  finds a live check-in. Both require a client that signs or calls `session_bind`.
  So registering an agent whose client does neither observes *nothing* — Phase 2's
  "watch the binding land in receipts" needs an instrumented client just as much
  as Phase 3 does. Registration only decides who gets *enforced* once the switch
  is on (D3).
- **A registered agent with an unreadable/short secret fails closed** (not open):
  `_enforce_binding_gate` pairs `agent_registry.load()` with `is_registered()` so a
  broken keystore denies rather than silently downgrading to manifest-only. An
  operator must repair `$WILLOW_HOME/gate/secrets/` to restore that agent.
- **`whoami` / `diagnostic_summary` cross-identity disclosure — CLOSED.** These
  tools are ungated (they must answer with an empty/missing manifest), so in stdio a
  caller could pass any `app_id` and read that identity's config (permissions/role/
  `store_scope`). They now route through `_own_identity_denial` → the same per-call
  credential check the gate uses: under enforcement you may only read the identity
  you can prove you own (whoami is unclassified, so identity proof, not a tier gate).
  No-op when enforcement is off (trusted-host single-operator model) or the app_id is
  unregistered — consistent with how `_gate` treats every other tool. Serve mode was
  already bound via OAuth.

### D4 — the declaration schema (settled by Phase 4)
The 13-field check-in header is the ENTRY declaration (already implemented, H1).
Only a subset is reconciled — the *did-diff* has no independent ground truth for
identity/crypto fields, so the reconciled set is `session_binder.RECONCILED_FIELDS`
= `{tools, pass_count, fail_count, drift, state_hash}`:
- **`tools`** is the willow-gate CLASS list (read/write/execute/admin), diffed
  against the receipt log. Ground truth is `ReceiptLog.distinct_tools(app_id,
  started_ts, outcome="ok")` — the DISTINCT set of tools that actually ran, scoped
  to the session window by a SERVER-stamped start time (never the agent-supplied
  `timestamp`), classified via `tier_policy`. It is a DISTINCT-tool query, not a
  row fetch, so a late privileged call in a high-volume session cannot fall outside
  a truncated window and read as clean. The agent cannot feed this list (H3).
- **`pass_count` / `fail_count` / `drift` / `state_hash`** are the agent's
  self-scored task metrics — willow-mcp has no independent ground truth, so they
  are *echoed* in the report, never judged.
Verdict `clean` is false only on a **privileged** discrepancy (a false
write/execute/admin claim, or privileged use not declared at entry/exit); read is
ambient (session_enter, self-reads), so read-level over/under-reporting is
surfaced but never fails a session. The session is dropped at check-out, freeing
its per-call used-nonce set (the H1 residual bound).

### D3 — the opt-in trigger (settled by Phase 3)
Two locks, not one, because turning enforcement on before a registered agent's
client can sign would brick it (an un-instrumented client cannot produce the
per-call signature, and that is by design — H1's whole point):
- **`WILLOW_MCP_ENFORCE_BINDING`** (env, read live) is the master switch. OFF by
  default ⇒ registering an agent is *exactly Phase 2* (observe-only): the operator
  can watch the binding land in receipts before it can deny anything.
- **Registration** is the per-agent trigger. With the switch ON, a *registered*
  app must present a valid signed per-call credential and clear the tier ceiling;
  an *unregistered* app stays manifest-only (a plain local clone keeps working
  with no HMAC ceremony). So the cutover is deliberate and reversible: register in
  observe mode, wire the client's signer, then flip the switch.
The `enforce_binding` global row in the gates panel makes the switch's live state
visible next to `strict_trust_root`.

~~Before any of this, upstream a fix (or a tracked issue) for willow-gate's
unenforced `entry_allowed`~~ — **done (2026-08-10).** `entry_allowed` is
enforced upstream at `willow_gate/__init__.py:280` (`if not level.entry_allowed`)
with coverage in `tests/test_willowgate.py`, closing willow-gate#12. Nothing
blocks the cutover on the willow-gate side.

~~Still open: write the read-universal policy call into the gate's docs so the
seam's read semantics are chosen, not inherited.~~ — **done (2026-08-10).**
willow-gate's README now states that `read` is granted by construction rather
than by tier, that Exiled is withheld by *entry* and not by `allowed_tools`, and
that an embedder must compose `host_acl(identity) ∩ tier_ceiling(trust_level)`
and stay fail-closed so the gate can only narrow a host's reads, never widen
them. This seam is cited there as the worked example.

**Both Phase 5 prerequisites are closed, and Phases 6-7 close the seam.** The
federated client signs its outbound calls (6) and can now reach a peer this
process did not spawn (7), which is what turns that signature from audit into
authentication. The mechanism is complete in both directions.

What remains is deployment, not construction: no downstream server is ratified
on this box, so nothing exercises the outbound path yet. The inbound survey in
the residuals above still stands — an IDE seat cannot sign, and registering one
buys nothing.

@phase constraints
## Verified against the running system (2026-08-27)

This doc was written 2026-08-10. Everything below was re-measured against
willow-mcp at **v2.18.0** — fourteen minors later — because a seam described but
never re-run is a seam you are trusting on its own say-so.

| claim | result |
|---|---|
| the two implementations agree on the wire | **byte-identical** canonical header; identical HMAC-SHA256 (`2135026c5780614b…` both sides) |
| the trust ceiling is bound, not asserted | `claim 4` against ceiling 2 → `BindError: trust claim 4 exceeds registered ceiling 2` |
| the funnel is still sole and complete (H2) | **121 `@_guarded` / 121 tool decorators**, exact 1:1 |
| `_gate` still yields a distinct identity | `effective_app_id` computed, and `call_kwargs["app_id"]` overwritten with it |
| receipts still record at the funnel (H3) | `bind_observed` / `bind_enforced`, `_announce_hook` attached |
| `examples/signing_client.py` | **PASS** end to end on the current build — signed write + read ok, unsigned denied, check-out reconciles clean |

willow-gate itself is **frozen, not drifted**: `main` is clean and identical to
`origin/main` at `9e75137` (2026-08-10). Two API details have moved out from
under this doc, and matter only if the package is ever installed alongside:

- `WillowGate.__init__(operator_key_fpr=None, base_dir=None, require_pgp=True)`
  — defaults to a hardcoded `/willowgate` base and PGP required, so a naive
  construction raises `PermissionError: '/willowgate'`. A bridge must pass both.
- willow-gate's own `registry.json` keeps `secret` inline; D2 above deliberately
  **splits** that (ceiling in the registry, secret in a `0600` sidecar). The two
  on-disk formats are not interchangeable.

Neither blocks anything today, because **willow-mcp never imports willow-gate** —
`agent_registry`, `session_binder` and the ceiling are all willow-mcp's own
stdlib-only code (D5). That is why the round-trip works despite the freeze.

## Deployment surface — nothing on this box can sign (2026-08-27)

The credential rides the MCP request's out-of-band `_meta`
(`CREDENTIAL_META_KEY`), so the **client** must hold the per-agent secret and
HMAC every call. That is what `examples/signing_client.py` is: not a test
fixture, but the production shape of a harness.

A census of what actually calls this server:

| app_id | IDE seats (rendered `.mcp.json`) | signed manifest |
|---|---|---|
| `willow` | **22** | yes |
| `heimdallr` · `jeles` · `utety` · `vishwakarma` · `nestor` | 1 each | yes |
| `ada` · `hanuman` · `loki` · `skirnir` | **0** | yes |

All 27 wired seats resolve through Claude Code or Cursor. Neither attaches
`_meta`; `_read_call_credential()` returns `None`, which for a **registered**
agent is a denial. So:

@constraint severity="critical"
Registering binds an **app_id, not a client**. Every seat on this box is driven
by an IDE client that cannot sign, so `register-agent X` + `ENFORCE_BINDING=on`
locks that seat out of its own tools. `willow` is 22 seats — registering it
would deny 22 projects at once. Register a seat only once something that can
sign drives it.

The four with manifests and `receive_dispatch: true` but **zero seats** are the
only harness-shaped identities today, and only if a dispatch is executed by a
harness rather than by a human opening a session as that agent — `session_enter`
hands a dispatched specialist its assignment, which is a session, i.e. a client.

**The Kart worker does not close this.** `worker.py` contains **zero**
occurrences of `_gate` or `_guarded`; it imports `task_queue`,
`egress_authorization`, `heartbeat` and `commitments`, and hands execution to
`kartikeya.run_worker` → `sandbox.run_shell`. Submit and execute are governed
separately, and correctly:

| | surface | governed by |
|---|---|---|
| `task_submit` | MCP tool | `@_guarded` → `_gate` → manifest, **and binding when enforced** |
| worker execution | daemon | sandbox mount policy + `ExecutorNetworkAuthorizer` (three-key egress lease) |

So the worker is not an unbound caller slipping past `_gate` — it is downstream
of a call that already went through it. A signing wrapper around the worker
would protect nothing that is not already protected.

**Conclusion.** No seat on this box both runs headless *and* calls MCP tools.
Binding therefore has no deployment surface here yet — a fact about this box's
shape, not a defect. `off` is the correct setting; `strict` (D3.1) is built and
waiting for the first thing that can sign: a dispatch runner, the grove's serve
mode with a signing client, or CI. D6's residual closes on that same day.

## Constraints

@constraint severity="critical"
- **H1 — session↔app_id binding is the whole ballgame (BLOCKER).** Every
  willow-mcp tool takes `app_id` as a plaintext string. The HMAC binds a
  *session*, but nothing ties a given MCP call to that session — a caller passing
  `app_id=operator` rides operator's live session with no auth of its own. **The
  full build must carry a per-call credential on every gated call; `app_id` alone
  cannot bind.** Largest change; touches every tool signature. *Prototyped — see
  "H1 prototype" below: a per-call HMAC signature (SIGNED) is the fix; a bearer
  session token closes the ride but not replay.*

@constraint severity="critical"
**CLI, never a tool** (same constraint as `confirm-binding` — stdio-only, host
that owns `$WILLOW_HOME`):
- `willow-mcp register-agent <agent_id> --max-trust N [--generate | --secret-file P]`
  — **requires an existing manifest** for `<agent_id>` (identity and ACL are
  provisioned together; the seam ties `agent_id == app_id`), generates a 32-byte
  secret when `--generate`, writes it `0600`, and prints it **once** for the
  operator to install in the client.
- `willow-mcp rotate-agent <agent_id>` / `revoke-agent <agent_id>` for lifecycle.
- All are authority acts — excluded from every permission group and unreachable
  from the MCP surface, upholding the sudo invariant.
