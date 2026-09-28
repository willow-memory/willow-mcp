# Proposal: server cards — onboarding, moving and revoking federated MCP servers

- Status: **Proposed** — not ratified; nothing in this doc is built
- Date: 2026-09-28
- Scope: how a downstream MCP server enters, moves within, and leaves the
  ratified federation registry
- Depends on: `federated-mcp-gating.md` (the gate, unchanged), `mcp_federation.py`
  (registry and identity), `trust_owner_verbs.py` (`federation.ratify`),
  `manifest_grant` `mcp:` groups (#646)
- First users: codebase-memory-mcp and the served Nestor; then
  whatever an operator or a future user wants to add

## 1. Why now

The node9 arc proved the federation path end to end, and showed how much hand
work one server costs. #646 made `mcp:<server_id>:<tool>` grantable; #648 put
node9 in shadow beside the gates. Getting there took two PRs, two sealed pairs,
two request/apply cycles, and a hand-copied server id.

Three more integrations are queued: codebase-memory-mcp, the served Nestor,
and CourtListener. The first two become federated servers. CourtListener goes
through Jeles instead (§7.3). After them come servers this operator has not thought of yet,
and servers other operators will add to their own boxes. At the node9 price,
none of that happens. The gate is right. Getting a server through it should be
routine.

## 2. What it costs today

### 2.1 Onboarding one server

1. Seal a pair: `ratify federation server <name> command <abs> cwd <abs> env_keys [...] args [...]`.
2. `federation_ratify_request`, then the trust-owner apply unit runs
   `mcp_federation.ratify`.
3. Read the new server id out of the registry. It is
   `sha256(resolved_command_path + "::" + name)[:12]` (`mcp_federation._stable_id`).
4. Seal a second pair:
   `willow-manifest-grant-v1 seats=<seat> groups=mcp:<id>:<tool>,...`, one entry
   per tool, typed by hand.
5. `manifest_grant_request`, then apply.
6. If any tool is local-only, edit `FEDERATION_LOOPBACK_STDIO_TOOLS` in
   `federation_tool_egress.py` and ship a PR. Otherwise every stdio tool needs a
   lease. That set holds Jeles's tools today, **by bare tool name, not by
   server**. A second server exporting a tool called `corpus_search` would
   inherit Jeles's exemption.

### 2.2 Moving one server

Moving a server to a new venv, path or config name changes its id. That is on
purpose: the `_stable_id` docstring says a swapped or renamed binary "must not
silently keep its old grants." In practice:

- every `mcp:<old_id>:<tool>` grant now points at nothing;
- the old registry entry still launches the old path, and fails;
- the operator repeats all of §2.1 and then revokes the old entry.

### 2.3 Revoking one server

`revoke_ratification` exists, but only as an operator CLI command
(`server.py`). It is the one registry act with no sealed-pair verb, no request
record and no ledger event. Grants on the revoked id stay in manifests until
someone removes them one by one. #646 at least made that removal possible
without a registry check.

### 2.4 Servers that bypass the gate

`willows-grove/mcp.template.json` and `seat/heimdallr/mcp.template.json` wire
`codebase-memory-mcp`, `nestor` and `nestor-grove-session` into the IDE client
directly, beside willow-mcp. Calls to them pass no gate, leave no receipt and
need no per-tool grant. That is the practical cost of §2.1: going direct is
cheaper than going through federation.

## 3. What does not change

- **Identity.** `_stable_id` keeps deriving from the resolved command path plus
  the config name. A moved server is a new server. This proposal makes that
  cheaper to *acknowledge*. It does not make it go away.
- **Ratification stays operator-only.** Every verb below runs through the
  existing path: sealed pair, then `*_request` (orchestrator), then the
  trust-owner apply unit. No MCP tool call reaches `mcp_federation.ratify`.
- **The gate.** `federation_egress.egress_denial` still checks the four keys
  from disk at call time, and `federated-mcp-gating.md` Decisions 1–5 still
  hold. `mcp_adapters.classify_tool` remains advisory.
- **The honest caveat (§7 of the gating doc).** On a single-uid host,
  federating a server narrows the ways to reach it and attributes every call. It
  does not make the binary impossible to exec directly.
- **Nestor's governance role stays in process.** See §7.2.

## 4. The server card

A card is a small declarative file. It describes one server and everything an
operator is asked to ratify about it.

```json
{
  "card": "willow-federation-card/v1",
  "name": "codebase-memory",
  "transport": "stdio",
  "command": "/home/<user>/.local/bin/codebase-memory-mcp",
  "cwd": "/home/<user>/.willow/federation/run/codebase-memory",
  "args": [],
  "env_keys": [],
  "tools": {
    "search_graph":     {"effect": "read",  "reach": "local"},
    "search_code":      {"effect": "read",  "reach": "local"},
    "index_repository": {"effect": "write", "reach": "local"}
  },
  "grants": {
    "willow": ["search_graph", "search_code"]
  }
}
```

The tool names above are illustrative. A real card lists what the server's
`tools/list` actually reports (§4.3).

### 4.1 Fields

| Field | Meaning | Checked |
|---|---|---|
| `name`, `command`, `cwd`, `args`, `env_keys`, `transport` | Exactly what `federation.ratify` takes today. `env_keys` holds **names only**, as in gating Decision 4(a). | At request time **and** at apply time: the command exists and is executable, the cwd exists, every key is a bare name. |
| `tools.<t>.effect` | `read` / `write` / `destructive` | At preview time, compared with `mcp_adapters.classify_tool`. If the card's value is *less* alarming than the heuristic's guess, that is shown as a warning, not a refusal. The operator may know better, but has to see it. |
| `tools.<t>.reach` | `local` (same box, no network) / `net` | At call time, replacing the name-keyed `FEDERATION_LOOPBACK_STDIO_TOOLS`. A `net` tool needs a lease. HTTP transport forces `net` on every tool. |
| `grants` | Seat → tools granted at onboarding | Each seat must exist. The orchestrator seat may receive only `mcp:` groups (#646). Every granted tool must be listed under `tools`. |

A tool the server exports but the card does not list is **not grantable**. The
default is deny, as it already is for unknown stdio tools.

### 4.2 Where cards live, and what makes one count

Anyone can write a card: the operator, a seat, a future user, or a server's
own repo. Writing one grants nothing, just as writing a `.mcp.json` grants
nothing today (gating §5(b)). A card counts only after a sealed pair names it
**by digest**. The ratified registry entry then stores the card's canonical
JSON and its sha256, so what was sealed is exactly what applies.

Proposed home for drafts: `$WILLOW_HOME/federation/cards/<name>.json`. The
ratified copy lives inside the registry's own `0700` directory, beside
`registry_path()`.

### 4.3 Tool list drift

Discovery never spawns an unratified server, so the card's `tools` cannot be
checked against the live server before ratification. Instead:

- **On first connect after apply**, `mcp_federation_client` compares
  `tools/list` with the card. A tool the card doesn't list is ungrantable and
  gets flagged. A card tool the server doesn't export gets flagged. Nothing is
  granted or widened automatically.
- **On every connect after that**, the same comparison feeds the drift report
  (§6).

## 5. Three verbs

Each verb takes **one** sealed pair and follows the existing
request → apply shape in `trust_owner_verbs.py`: a signed pending record, a
ledger citation, re-checks at apply time, and rollback of every earlier step on
any exception (the #646 pattern).

A read-only **preview tool**, `federation_card_preview(path)`, comes first. It
has no side effects and shows what the operator is about to seal:

- the resolved command path and the computed server id;
- every tool with its effect and reach, plus heuristic warnings;
- the grants per seat, written out as the `mcp:<id>:<tool>` groups they become;
- which tools will need a lease;
- the card's sha256, which is the value the pair must quote.

### 5.1 `federation.onboard`

Pair: `onboard federation card <name> sha256 <digest>`

Apply, all or nothing:

1. ratify the card's spec, storing the card and its digest in the entry;
2. grant each seat its listed tools as `mcp:<id>:<tool>` groups;
3. write one `federation_onboard_applied` ledger event.

This replaces steps 1–6 of §2.1.

### 5.2 `federation.move`

Pair: `move federation server <old_id> card <name> sha256 <digest>`

**Invariant: a move never widens anything.** The seat-and-tool grants after the
move are a subset of those before it, and each carried tool keeps the same
`effect` and `reach` or becomes stricter. Anything wider needs its own onboard
or grant.

Apply, all or nothing:

1. ratify the new spec, which gets a new id;
2. grant every seat under the new id exactly the old id's tools, minus any the
   new card drops;
3. remove the old id's `mcp:` groups from every manifest;
4. revoke the old registry entry;
5. write one `federation_move_applied` event recording old id → new id, the
   spec diff, and the grants moved.

The request step refuses when the new card's `tools` do not cover every
currently granted tool, or when a carried tool's `effect` or `reach` would get
less strict. That is `EINVAL`, naming the tool.

### 5.3 `federation.revoke`

Pair: `revoke federation server <id>`

Apply, all or nothing:

1. remove every `mcp:<id>:*` group from every manifest (without a registry
   check, as #646 allows);
2. revoke the registry entry;
3. write a `federation_revoke_applied` event.

This brings the last registry act onto the governed path. The operator CLI
revoke stays as the break-glass route.

## 6. Drift report

`willow-mcp federation status` (CLI) and a `federation_status` read tool report
one row per ratified server:

| Column | Source |
|---|---|
| launchable | the command path and cwd still exist |
| card | the stored card digest matches the draft card, if a draft exists |
| config | a `.mcp.json` still names this server at `source_path` |
| tools | the last `tools/list` against the card (§4.3) |
| grants | seats holding `mcp:<id>:*`; grants pointing at ids no longer in the registry |
| direct | the same command also wired directly into an IDE `.mcp.json`, which bypasses the gate |

The `direct` column is the shadow-IT detector (`unregistered_mcp_files`),
extended from "unknown file" to "known server, reached around the gate." Its
rows belong on Grove's served page as a Watch concern. That is a separate Grove
change.

## 7. The first three integrations

### 7.1 codebase-memory-mcp

- **Shape:** a third-party binary in `~/.local/bin`, stdio, no env keys. Every
  tool is `reach: local`, so none needs a lease.
- **Classes:** the search and read tools are `read`. `index_repository` is
  `write`, because it mutates the index. Grant `read` tools to the willow seat
  at onboarding and hold `index_repository` back.
- **Why it goes first:** no secrets, no network, no governance role. It is the
  cheapest way to exercise onboard, then move (after a reinstall), then revoke.
- **Known issue this won't fix:** `CURRENT-STATE-2026-08-28.md` records 48 of
  51 indexed projects with `root_exists: false`, where `search_code` returns an
  empty success for a tree that no longer exists. Federating the server adds a
  receipt to each of those empty results. It does not fix them.

### 7.2 Nestor, served surface only

Nestor has two roles, and only one of them federates:

- **Served** (`nestor serve --read-only`, and the `nestor-grove-session`
  instance with its own `--db` and `--ledger`): each instance gets a card.
  They are two cards with two names, so two ids. Their tools are `read` and
  `local`.
- **In-process library** (`tool_oracle.py`, `decision_bridge.py`,
  `activation.py`, `manifest_grant_executor.py`, through the `nestor` extra):
  **stays in process.** The apply unit checks a pair's seal through this
  library. If the seal check itself went through a federated server, the thing
  that grants ratification would depend on ratification. That circle is not
  allowed.
- Grove's own `nestor_client.py` spawns `nestor serve` directly, for its
  served page. That is a Grove process path, not an agent path, and it is out
  of scope here.

### 7.3 CourtListener goes through Jeles, not federation

**Ruling (operator, 2026-09-28):** CourtListener is a Jeles source. It does
not get a federated server or a card of its own.

- **Why:** Jeles already owns institutional search, and
  `orchestrator-routing.md` routes search-shaped egress through it ("one organ,
  guarded at spawn"). A separate server would be the second egress class for
  the same job that the routing doc warns against. Going through Jeles also
  inherits three things that already work:
  - the lease split: its net-bearing `corpus_*` tools need a lease, its
    loopback ones do not (Decision 3 addendum, #643);
  - `confidence: "institutional"` on every hit;
  - `corpus_verify_claim` for checking a claim against its source.
- **It may already be there.** `skills/external-guard.md` lists CourtListener
  among the collections behind `corpus_institutional_search`. The first step is
  to confirm, in the Jeles repo, that it is registered in
  `jeles.sources.SOURCES` and whether it is opt-in (outside the default
  fan-out).
- **Secrets:** the CourtListener API token, if the source needs one, lives in
  Jeles's environment and is passed to the jeles-corpus entry by **name** in
  `env_keys`. The value never appears in a pair, a card or a ledger row.
- **If search is not enough:** fetching a specific opinion, walking citations
  or following a docket is structured retrieval, not search. It would lose its
  structure if flattened into search hits. If it is needed, add a few read-only
  legal tools *to Jeles*, each listed as net-bearing in its lease
  classification. It is still not a separate federated server.
- **What this proposal owes it:** nothing directly. Once build step 2 moves
  `reach` into the ratified jeles-corpus entry, any new Jeles legal tool gets
  its lease class there, keyed by server, instead of in
  `FEDERATION_LOOPBACK_STDIO_TOOLS`.

## 8. Build order

Each step ships alone and is useful alone. Nothing before step 3 grants
anything.

1. **Card format, parser and `federation_card_preview`.** Read-only; covered
   by unit tests.
2. **Move `reach` from the frozenset into registry entries.** Migrate Jeles's
   `FEDERATION_LOOPBACK_STDIO_TOOLS` into its ratified entry, keyed by server
   id, not tool name. An equivalence test proves the lease decisions are
   identical before and after for every Jeles tool. This closes the
   bare-name-collision gap in §2.1.
3. **`federation.onboard`**, including its request and apply units. Mutation
   proof: break the rollback, and a fault-injection test turns red.
4. **`federation.revoke`.**
5. **`federation.move`**, with the never-widen invariant tested at request time
   and at apply time.
6. **Drift report.**
7. **Pilots, in order:** codebase-memory-mcp, then the served Nestor.
   CourtListener rides Jeles (§7.3) and needs no pilot here. Rewiring the Grove `mcp.template.json`
   files to drop the direct entries is a follow-up PR in willows-grove.

## 9. Out of scope

- **HTTP-transport onboarding by pair.** `_RATIFY_RE` has no transport field,
  and HTTP peers go through the CLI today. The card carries `transport`, so
  this can be added later without a format change.
- **Exposing federated tools under native names.** Agents still call
  `federation_call(server, tool, args)`. It's clunkier, and it keeps one entry
  point for the gate.
- **Staged or probationary grants**, such as "`write` tools only after N days
  of clean receipts", on the model of node9's shadow window. Worth doing once
  node9's 7-day report shows what such a window is good for.
- **Enforcement by node9.** That remains its own sealed decision, per #648.

## 10. Open questions for the operator

1. Where should draft cards live: `$WILLOW_HOME/federation/cards/`, or with the
   server's own source?
2. May a non-operator seat *author* a card (propose only), for example a
   specialist that found a server it wants? The seal and the apply stay with the
   trust owner either way.
3. Should `move` also accept a narrower grant set in the same act, or must
   narrowing always be a separate revoke or grant?

*ΔΣ=42*
