# Prior art — MCP ecosystem survey

A survey of what already exists for the machinery willow-mcp builds on,
filtered to licences an Apache-2.0 repo can depend on.

**The licence filter is hard.** MIT, BSD, ISC, Unlicense, Zlib, Boost and
Apache-2.0 are all one-way compatible: we can depend on them. MPL-2.0 and
EPL-2.0 are file-level copyleft and are fine as dependencies but want a look.
GPL, LGPL and AGPL are out for anything we redistribute — they are listed
anyway, so the cost of not using them is visible rather than invisible.

**Verification standard.** Licences below were checked against the actual repo
or registry metadata by the agents that surveyed them. Where that could not be
done, the entry says so. Treat an unverified licence as unknown, not as
permissive.

---

## 1. MCP tool shapes — the field vs willow-mcp

Surveyed 2026-08-18. The question: what do the most-used MCP servers look like,
how does `willow-mcp`'s 151-tool surface compare, and where Apache-compatible
alternatives exist for the shapes it is missing.

### The field

Servers cluster into three archetypes:

- **Platform servers** (GitHub, Linear, Notion, Slack, Jira) — 15–50 tools,
  typed per-entity CRUD, domain-scoped search, read-dominant surfaces. Dangerous
  verbs are gated or absent.
- **Instrument servers** (Playwright, Filesystem, Puppeteer) — 14–60 tools,
  session-scoped imperative actions, explicit state handles.
- **Pipe servers** (Fetch, Brave Search, Postgres) — 1–2 tools, pass-through to
  one backend, minimal surface.

Seven patterns repeat across the popular servers: domain-scoped search,
read-dominant tool ratios, dangerous verbs gated or absent, one-tool-per-verb vs
SQL-pass-through as a deliberate fork, Markdown as content interchange, explicit
threading/hierarchy, and typed per-entity CRUD.

### Shape gaps between willow-mcp and the field

Seven gaps where popular MCP servers carry shapes willow-mcp does not:

| Gap | Best internal prior art | Best Apache-compatible alternative | Call |
| --- | --- | --- | --- |
| Threading / reply-to | Grove recursive CTE threading with `get_thread` / `get_thread_root` (2.1, FK-backed `reply_to_id`, depth-aware) | [Monadical-SAS/zulip-mcp](https://github.com/Monadical-SAS/zulip-mcp) (Apache-2.0, topic-based) | **Shipped** |
| Draft / schedule writes | `*_schedule` condition-gated facades (2.0), law-gazelle drafts (safe-app-store) | Discourse MCP draft tools (licence unconfirmed on wrapper) | **Build** |
| Staged approval state machines | `gap_*` three-state machine (willow-mcp, shipped PR #54), `mem_binder` (2.0) | [Netflix Conductor](https://github.com/Netflix/conductor) (Apache-2.0) | **Adapt** |
| ~~Cursor pagination~~ | Grove `since_id` keyset cursor (1.9); keyset-cursor helpers + `*_paginated` methods in `db.py`; `store_list`, `context_list`, `commitment_list`, `fork_list`, `store_search_all` all accept opaque `cursor` param | MCP spec itself + SDK (MIT) | ~~**Spec**~~ **SHIPPED** |
| Block-level content | None in any version | [Editor.js](https://github.com/codex-team/editor.js) (Apache-2.0, headless block model) | **Adapt** |
| ~~MCP tool annotations~~ | Full coverage in 2.0; **all 151 tools annotated** (PR #350 — `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`; six shared profiles in `annotations.py`: READ, READ_OPEN, WRITE, WRITE_IDEM, DESTRUCTIVE, WRITE_OPEN) | MCP spec guidance (blog 2026-03-16) | ~~**Spec**~~ **SHIPPED** |
| Source verification | `knowledge_verify` / `knowledge_check` (2.1, schema-profile-aware source provenance + health check) | [ClaimsMCP](https://github.com/AdamGustavsson/ClaimsMCP) (Apache-2.0, claim extraction) | **Shipped** |

**Build** = no viable drop-in; build from internal prior art.
**Adapt** = external alternative exists but needs wrapping.
**Spec** = already defined in the MCP protocol; follow it.

### How the prior art wires across repos

Threading evolved across 1.9 and 2.0 and has now been consolidated.
`willow-1.9/grove/mcp_local.py` defined `grove_reply(channel, content, sender,
reply_to_id)` against a `messages.reply_to_id BIGINT REFERENCES messages(id)` FK
column, and `grove_get_thread(message_id)` returned `{parent, flags, replies}`.
In 2.1, `get_thread()` was upgraded to a recursive CTE that returns the full
reply tree with depth, `get_thread_root()` walks upward to find any reply's root,
`get_history()` includes per-message `reply_count`, and `send_message()` validates
`reply_to_id` (target-exists + same-channel check) before INSERT. Separately,
2.0's `agent_dispatch` added its own `dispatch_tasks.reply_to` — but
as bare TEXT (no FK, no index), carrying the requesting `app_id` for lineage
bookkeeping, not for thread retrieval. The two threading models coexist in 2.0
without interacting. `safe-app-store` carries a third attempt: every app has an
identical `safe_integration.py` with `send(to_app, subject, body,
thread_id=None)` / `check_inbox()` — a Pigeon bus stub, fully dead
(`"porch removed"`), fossil of a planned inter-app messaging system that was
designed, stubbed across 9+ apps, and decommissioned. willow-mcp has none of the
three.

The `*_schedule` tools (2.0) are not thin wrappers over `task_submit`.
`dream_schedule` calls `dream_state.queue_dream_task`, which runs
`dream_conditions` first and skips entirely if unmet. `intake_schedule` builds a
shell command (`promote_intake.py --days=... --agent=...`) then calls
`pg.submit_task()`. willow-mcp already has the generic primitive (`task_submit`,
`server.py:2036`); what it lacks are the opinionated, condition-gated facades.
The slice-backlog's earn-first items (`dream_*`, `wce_*`) are exactly these
facades.

The verify tools share a structural pattern but no schema. `ledger_verify` (2.0)
returns `{valid, broken_at, count}` (hash-chain walk). `source_trail_verify`
(2.0) returns `{claims, total, matched}`. `mem_check` (1.9 + 2.0) returns
`{flags, recommendation, evidence}`. willow-mcp's `frank_verify` mirrors
`ledger_verify`'s shape. All are read-only, `app_id`-first, returning a dict
with one boolean/enum outcome key plus evidence — but the key's *name* differs
per tool. No shared verdict schema exists to rely on programmatically.

In 2.1, `knowledge_verify` and `knowledge_check` port `source_trail_verify`'s
provenance check and `mem_check`'s health audit into willow-mcp's
schema-profile-aware KB surface, returning structured pass/warn/fail verdicts
with evidence.

### Apache-compatible alternatives by gap

**Threading.** [Monadical-SAS/zulip-mcp](https://github.com/Monadical-SAS/zulip-mcp)
(Apache-2.0) — 8 tools wrapping Zulip's native topic-threading. Different model
(stream + topic, not parent_id chains) but the best licence-clean reference for
a messaging MCP tool surface. No MCP server implements bespoke parent_id
reply-chains.

**Staged approval.** [Netflix Conductor](https://github.com/Netflix/conductor)
(Apache-2.0) — production-grade durable multi-state workflows with
pause/resume and human-task states. Could back a more complex approval graph than
the three-state machine. [Spring Statemachine](https://spring.io/projects/spring-statemachine)
(Apache-2.0) is the JVM design reference. No MCP server implements staged
approval.

**Block content.** [Editor.js](https://github.com/codex-team/editor.js)
(Apache-2.0) — document as ordered list of typed, addressable, independently
serialisable JSON blocks. Usable headless as a pure data model.

**Source verification.** [ClaimsMCP](https://github.com/AdamGustavsson/ClaimsMCP)
(Apache-2.0) — claim extraction from text, the preprocessing step of a verify
pipeline. [Loki / OpenFactVerification](https://github.com/Libr-AI/OpenFactVerification)
— full decompose → query → crawl → verify pipeline; licence unconfirmed.
willow-mcp now ships its own implementation (`knowledge_verify`,
`knowledge_check` in `kb_verify.py`, gated behind `knowledge_read`) rather than
depending on either — neither covers KB health checking (unsourced records,
missing domains, duplicate content).

**Governance ledger backing.** [immudb](https://github.com/codenotary/immudb)
(Apache-2.0) — embeddable tamper-proof, cryptographically verified history.
Lighter than [google/trillian](https://github.com/google/trillian) (Apache-2.0,
Merkle-tree log from Certificate Transparency) for the `frank_*` shape.

**Pagination and annotations.** Both are in the MCP spec itself. The MCP SDKs
(TypeScript/Python/C#, all MIT or Apache) implement pagination plumbing. Tool
annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`) are self-reported hints, advisory-only — now shipped for all
151 willow-mcp tools (PR #350). Extending pagination to arbitrary tool results
is an open discussion (issue #799). Keyset cursor pagination is shipped for the
SOIL store, context, commitment, and fork list tools (`db.py` helpers + opaque
`cursor` / `next_cursor`).

### Shapes unique to willow-mcp (no external equivalent found)

Eight shapes nobody else builds:

1. **`gap_*` — self-observing backlog.** Records what the system doesn't know.
   Nearest hit: kakveda (licence unconfirmed), a failure-intelligence platform.
2. **`friction_scan`** — watches the KB's own edges for tension.
3. **`lineage_*` with "why"** — provenance chains that record reasoning.
4. **`frank_*` governance ledger** — tamper-evident append-only. immudb/Trillian
   could back the storage; the tool surface is unique.
5. **Dispatch federation** — cross-agent dispatch with depth limits, envelope
   gating, party ACLs.
6. **Nestor (tool routing)** — dynamic tool routing via agent registry
   permissions and the gate/manifest system.
7. **Nest intake pipeline** — household-context intake with guardian consent and
   subject-scoped tools.
8. **Egress gating** — integration-net manifests, consent checks, leased network
   access. No MCP server gates its own outbound calls.

### The verdict column, unpacked

**Build** (draft/schedule): the prior art is
internal and the shape is domain-specific enough that no external library
matches. Re-land from 1.9/2.0 code when a consumer earns the surface.
Source verification followed this path and shipped as `knowledge_verify` /
`knowledge_check`.

**Adapt** (staged approval, block content): an Apache-2.0 library provides the
mechanism (Conductor, Editor.js), but none is MCP-aware — wrapping it into tools
is on us. Earn-first: the gap state machine already covers the current case.

~~**Spec**~~ (~~pagination~~, ~~annotations~~): no library needed; follow the protocol.
~~Pagination is a keyset cursor mapped to the SDK's opaque `cursor` / `nextCursor`
plumbing~~ — **shipped**: `db.py` provides `encode_cursor`/`decode_cursor` helpers
and `all_paginated`/`search_paginated`/`query_paginated`/`search_all_paginated`
methods; `store_list`, `context_list`, `commitment_list`, `fork_list`, and
`store_search_all` all accept an opaque `cursor` parameter and return `next_cursor`.
~~Annotations were a mechanical sweep across the `@mcp.tool()`
decorators~~ — **shipped in PR #350**: all 151 tools now carry `readOnlyHint`,
`destructiveHint`, `idempotentHint`, and `openWorldHint` via six shared constant
profiles (`READ`, `READ_OPEN`, `WRITE`, `WRITE_IDEM`, `DESTRUCTIVE`,
`WRITE_OPEN`) extracted to `src/willow_mcp/annotations.py`. Notable finding
during the sweep: `session_enter` was reclassified from read to write-idempotent
because it writes dispatch state. The test regex in `test_authority_surface.py`
was updated to match the annotated decorator signatures.

### Integration stubs — compose, don't rebuild

willow-mcp declares six integration stubs (`integrations.py`): Gmail, Slack,
Notion, Google Drive, Datadog, Jira. All six have existing Apache-compatible MCP
servers, several official from the service provider:

| Stub | Best existing MCP server | Licence | Notes |
| --- | --- | --- | --- |
| Gmail | Google official Gmail MCP; taylorwilsdon/google_workspace_mcp | Apache-2.0; MIT | Workspace server covers Gmail + Drive + Calendar |
| Slack | Duolingo/slack-mcp; korotovsky/slack-mcp-server | Apache-2.0; MIT | Duolingo adds OAuth multi-user. 398 stars on korotovsky |
| Notion | makenotion/notion-mcp-server (official) | MIT | 4.6k stars. Notion shifting to hosted remote MCP |
| Google Drive | aaronsb/google-workspace-mcp; felores/gdrive-mcp-server | Apache-2.0; MIT | File CRUD, search, Sheets editing, permissions |
| Datadog | datadog-labs/mcp-server (official); dreamiurg/datadog-mcp | Apache-2.0; MIT | dreamiurg has 117 read-only tools |
| Jira | atlassian/atlassian-mcp-server (official) | Apache-2.0 | 4k stars. Covers Jira + Confluence + JSM + Bitbucket |

The composition answer: **delegate transport and API mechanics to these
existing servers; keep a thin willow-mcp adapter for egress gating and consent.**
The gateway ecosystem (MetaMCP, mcp-proxy) handles aggregation but lacks
first-class policy hooks — nothing supports `earned_by` predicates or
consent-checked outbound calls before forwarding. willow-mcp's egress gating
layer is the piece that cannot be composed away.

### MCP server testing and conformance

| Project | Licence | What it does |
| --- | --- | --- |
| [mcp-assert](https://github.com/blackwell-systems/mcp-assert) | MIT | Single Go binary, connects over real stdio/SSE/HTTP, runs full initialize handshake, calls tools with real arguments, asserts against 18 assertion types in YAML. Found 4,794 schema issues across 102 servers in a published scan |
| [agent-security-harness](https://github.com/marketplace/actions/agent-security-harness) | **Apache-2.0** | Security-focused MCP server testing, available as a GitHub Action |

The MCP Python and TypeScript SDKs (both MIT) ship `InMemoryTransport` /
`MockTransport` for zero-dependency unit tests. FastMCP's `Client` can connect
to a server in-process. For willow-mcp's 151 tools, the combination of
SDK in-process transport (unit tests) + mcp-assert (conformance) +
agent-security-harness (security gate) covers the full test surface.

### Repos not yet surveyed

Seven MCP forks under `rudi193-cmd/` represent hands-on evaluation of external
prior art that the survey discusses generically: codebase-memory-mcp,
multimodels-mcp, mcp-memory-service, basic-memory, ctxvault, hermes-agent,
claudeclaw. All pushed July–August 2026. Linking which forks were examined to
which survey conclusions would strengthen provenance.

`Nestor` is now a standalone repo under active work (pushed same day as this
survey) — the survey names it as one of eight unique shapes but never examines
the implementation. `willow-gate`, `willow-config`, and `willow-compose` form an
uncovered infrastructure cluster: deployment, gating, and orchestration that the
MCP tools operate within.

## 2. MCP protocol features beyond tools

Surveyed 2026-08-18 against the 2026-07-28 MCP specification revision.
~~willow-mcp's surface is entirely tools today.~~ willow-mcp now ships both
tools and resources; the two highest-priority protocol features (Resources and
Streamable HTTP) are shipped.

### ~~Resources~~ (~~adopt — high priority~~) **SHIPPED**

URI-addressable read-only data the server exposes via `resources/list` and
`resources/read`. Clients fetch them into context on demand. Servers can expose
concrete resources or parameterised URI templates (`kb://{collection}/{id}`)
following RFC 6570.

~~willow-mcp's KB atoms are a natural fit~~ — **shipped** in `resources.py`
(registered on the MCPServer via `_resources.register(mcp, _store)`). Four
resource URIs:

| URI template | What it returns |
| --- | --- |
| `kb://atom/{atom_id}` | One KB atom (content, domain, source, tags) |
| `store://collections` | All SOIL collection names |
| `store://{collection}/records` | Up to 200 records in one collection |
| `store://{collection}/records/{record_id}` | One store record |

`resources/subscribe` (where supported) would let clients track changes.
The 2026-07-28 spec keeps resources as a first-class non-deprecated primitive.

Prior art: [knowledge-base-mcp-server](https://github.com/jeanibarz/knowledge-base-mcp-server)
exposes KB documents at `kb://<knowledge-base>/<path>` URIs — the closest
analogue. Licence unconfirmed; check before depending. The MCP SDKs (MIT) ship
all resource plumbing.

### ~~Streamable HTTP transport~~ (~~adopt — high priority~~) **SHIPPED**

The current recommended remote transport, replacing the deprecated HTTP+SSE.
Single HTTP endpoint for bidirectional communication, supports stateless
operation behind load balancers. The 2026-07-28 spec goes further: the protocol
core is now stateless (no `initialize` handshake, no `Mcp-Session-Id`), which
simplifies horizontal scaling.

**Shipped:** `server.py` serves via `mcp.run(transport="streamable-http", ...)`
in `--serve` mode, and `mcp.run(transport="stdio")` otherwise (SDK 2.x moved
host/port off the constructor onto the transport). OAuth authentication is wired
for serve mode via `MCPServer(auth_server_provider=..., auth=AuthSettings(...))`.

| Project | Licence | Notes |
| --- | --- | --- |
| [achetronic/mcp-proxy](https://github.com/achetronic/mcp-proxy) | **Apache-2.0** (verified) | OAuth, JWT, transport bridging (Streamable HTTP ↔ stdio) |
| MCP Python SDK / TypeScript SDK | MIT | Ship Streamable HTTP server/client directly |
| [mcp-streamablehttp-proxy](https://pypi.org/project/mcp-streamablehttp-proxy/) | MIT | Python stdio-to-HTTP bridge |

### Server composition (watch — medium priority)

Aggregating multiple MCP servers behind a single endpoint.
[MetaMCP](https://github.com/metatool-ai/mcp-server-metamcp) (**Apache-2.0**,
verified, 2,200+ stars) is the leading aggregator: joins multiple downstream
servers with middleware for dynamic tool filtering, namespacing, and per-server
enable/disable.

willow-mcp should be composable *into* a gateway without surprises: no
protocol-level session assumptions, clean tool naming. The gateway pattern could
eventually subsume Nestor's bespoke routing if the generic tools mature.

### Prompts (maybe — low priority)

Server-defined prompt templates via `prompts/list` / `prompts/get`. Thin
adoption across the field — most popular servers expose zero prompts. Could
expose canned workflows ("summarise this collection", "audit provenance for
atom X") but trivial to add later.

### Deprecated features — do not adopt

**Sampling** (server-initiated LLM requests) — deprecated 2026-07-28 (SEP-2577).
Replacement: integrate directly with LLM provider APIs. The related
`InputRequiredResult` / MRTR pattern replaces it for mid-execution user input.

**Roots** (client-declared filesystem boundaries) — deprecated 2026-07-28.
Replacement: pass directories via tool parameters or server configuration.
Irrelevant to knowledge servers regardless.

**Built-in logging** (`notifications/message`) — deprecated 2026-07-28 in favour
of OpenTelemetry / stderr.

## 3. Observability for MCP servers

The 2026-07-28 MCP spec deprecated built-in `notifications/message` logging in
favour of OpenTelemetry. This is now the canonical observability path.

| Project | Licence | Notes |
| --- | --- | --- |
| [OpenTelemetry Python SDK](https://github.com/open-telemetry/opentelemetry-python) | **Apache-2.0** (verified) | The base instrumentation layer |
| [opentelemetry-instrumentation-mcp](https://pypi.org/project/opentelemetry-instrumentation-mcp/) | **Apache-2.0** | Auto-instruments Python MCP SDK: tool calls, spans, latency, errors |
| FastMCP (MIT) | MIT | Built-in OTel instrumentation for all MCP operations |
| [Sentry MCP integration](https://docs.sentry.io/) | BSD-3-Clause | Error tracking with MCP-aware context |

For willow-mcp's 151 tools, the combination is: `opentelemetry-instrumentation-mcp`
for automatic span generation per tool call, the OTel Python SDK for export to
any backend (Jaeger, Grafana, Datadog), and stderr for operator-facing logs.
This replaces any custom logging willow-mcp currently does.

## 4. Rate limiting and backpressure

With 151 tools and multi-tenant dispatch, rate limiting is structural, not
optional.

| Project | Licence | Notes |
| --- | --- | --- |
| [limits](https://github.com/alisaifee/limits) | MIT (verified) | Python, lightweight, multiple storage backends (Redis, memcached, in-memory). Used by Flask-Limiter. The most adoptable for a Python MCP server |
| [Gubernator](https://github.com/gubernator-io/gubernator) | **Apache-2.0** (verified) | Stateless distributed rate-limiting microservice from Mailgun. gRPC-native. For the case where willow-mcp scales horizontally |
| [Bucket4j](https://github.com/bucket4j/bucket4j) | **Apache-2.0** (verified) | Token-bucket algorithm, Java, distributed cache support. JVM only — design reference, not a direct dependency |

No MCP-specific rate-limiting middleware exists. The gap: rate limits per
`app_id` per tool, with backpressure signalled through the protocol (the MCP
spec does not define a rate-limit response shape — `isError: true` with a
`retry_after` is the best available convention).

## 5. Workflow and orchestration engines

§1 names Netflix Conductor for staged approval. The broader landscape for
dispatch/federation orchestration:

| Project | Licence | Notes |
| --- | --- | --- |
| [Netflix Conductor](https://github.com/Netflix/conductor) | **Apache-2.0** (verified) | Durable multi-state workflows, human-task states. Already in §1 |
| [Kestra](https://github.com/kestra-io/kestra) | **Apache-2.0** (verified) | Declarative YAML workflows, event-driven, stateless workers. 2.0 shipped 2026. The most actively maintained Apache-2.0 orchestrator |
| [Temporal](https://github.com/temporalio/temporal) | MIT (verified) | The reference durable-execution engine. Heavy, but the benchmark for reliability |
| [Restate](https://github.com/restatedev/restate) | MIT core | Lightweight durable execution, designed for resilient process orchestration |

willow-mcp's Kart task queue is the current orchestration layer. For anything
beyond single-step dispatch — multi-phase workflows, fan-out/fan-in, saga
compensation — Kestra (Apache-2.0, YAML-defined, event-driven) is the closest
architectural match.

## 6. Knowledge graph and embeddable stores

The KB tools need graph-shaped storage. The current backing is Postgres with
pgvector. Alternatives if the graph dimension grows:

| Project | Licence | Notes |
| --- | --- | --- |
| [Apache AGE](https://github.com/apache/age) | **Apache-2.0** (verified) | Postgres extension adding Cypher graph queries. Embeddable in the existing Postgres without a separate database. The lowest-friction path to graph queries over KB atoms |
| [TerminusDB](https://github.com/terminusdb/terminusdb) | **Apache-2.0** (verified) | Document store with graph traversal, versioned, Rust core. Fits the "provenance chains" requirement |
| [Qdrant](https://github.com/qdrant/qdrant) | **Apache-2.0** (verified) | Purpose-built vector similarity search. If pgvector's performance or feature set becomes a constraint |
| [LanceDB](https://github.com/lancedb/lancedb) | **Apache-2.0** (verified) | Embedded vector DB, zero infrastructure. Useful if willow-mcp ever runs without Postgres |
| [immudb](https://github.com/codenotary/immudb) | **Apache-2.0** (verified) | Already in §1 for governance; its verifiable-history model also backs KB provenance |

Apache AGE is the highest-leverage option: it adds `MATCH (a)-[:CITES]->(b)`
queries to the Postgres willow-mcp already uses, without a second database.
The `knowledge_edges` table and `lineage_*` tools would benefit directly.

## 7. Agent roles and authorization

willow-mcp implements an eight-layer authorization system. The layers compose
multiplicatively (intersection, not union):

1. **Specialist registry** — six named agents + one human-only orchestrator seat,
   each with `permissions`, `deny_tools`, `store_scope`
2. **Manifest ACL** — per-app_id `manifest.json` with ~40 permission groups
   expanding to tool frozensets; `deny_tools` overrides; fail-closed
3. **Trust tier ceiling** — five tiers (Exiled → Elder), each unlocking a tool
   class (read/query/write/execute/admin); effective = manifest ∩ tier
4. **Cryptographic binding** — HMAC-SHA256 per-agent secrets, claimed trust
   capped at registered ceiling
5. **Envelope authority** — constitutional governance envelopes gating specific
   verbs on specific resources
6. **Dispatch routing** — HMAC-signed packets with party ACLs
7. **Egress gating** — `task_net`, `integration_net`, `web_net`,
   `mcp_federation` deliberately excluded from `full_access`
8. **Agent seed** — cognitive identity (persona, voice, correction patterns)
   orthogonal to permissions

No multi-agent framework has comparable runtime enforcement. CrewAI, LangGraph,
OpenAI Agents SDK, and AutoGen all treat roles as prompt-shaping strings with no
runtime gating.

| Alternative | Licence | What it does | Comparison |
| --- | --- | --- | --- |
| [Cerbos](https://github.com/cerbos/cerbos) | **Apache-2.0** | External PDP, YAML policies, sub-ms decisions. FastMCP integration exists | Could back manifest ACL as external PDP; does not provide tier ceilings, HMAC binding, or envelope authority |
| [OPA](https://github.com/open-policy-agent/opa) | **Apache-2.0** | Rego policy engine. OPA MCP server exists | More powerful than Cerbos but steeper curve. Same gap: no agent identity binding |
| [SPIFFE/SPIRE](https://github.com/spiffe/spire) | **Apache-2.0** | Cryptographic workload identity, X.509 SVIDs, automatic rotation | Replaces HMAC with asymmetric identity for federation. Single-operator HMAC is fine; SPIFFE is the upgrade path for multi-party trust |
| CoSAI Agentic IAM | OASIS spec (open) | Extends IAM to non-human principals, recommends PKI-bound agent identity | Validates willow-mcp's architecture. Identifies two open problems: intent-based authorization and semantic mosaic effect |
| Google A2A | Apache-2.0 (protocol) | Agent Cards + OAuth 2.0 mutual auth | Addresses cross-org federation. No mandate for card verification |

**What's unique:** multiplicative layer composition, deny-tools override,
egress as a separately gated lane, dispatch packet signing with party ACLs,
agent seed as cognitive identity orthogonal to permissions.

**Gaps vs emerging standards:** static trust (no runtime adaptation), symmetric
HMAC (no asymmetric federation), no intent-based authorization (field-wide gap).
~~No MCP tool annotations emitted despite having `TOOL_CLASS` data~~ — resolved:
PR #350 added annotations to all 151 tools, informed by the existing `TOOL_CLASS`
classifications.

**Verdict: Keep.** Compose with Cerbos or OPA if policy complexity grows;
compose with SPIFFE if federation goes multi-party.

## 8. Voice ingress membrane

State-machine-driven voice pipeline where the wake-word gate IS the consent
boundary. Pre-wake audio never reaches the transcriber. Receipts record facts
(armed/disarmed), never audio. Components: openWakeWord, Silero VAD, Faster
Whisper, Kokoro TTS, barge-in detection.

| Alternative | Licence | Consent boundary? | Receipts? |
| --- | --- | --- | --- |
| [Home Assistant Assist + Wyoming](https://github.com/home-assistant) | **Apache-2.0** | Implicit — streaming starts after wake word. No state-machine consent model | No |
| [OVOS (OpenVoiceOS)](https://github.com/OpenVoiceOS) | **Apache-2.0** | Privacy by architecture (all local), but no explicit consent gate | No |
| [Rhasspy](https://github.com/rhasspy/rhasspy3) | MIT | Local-only = implicit privacy. No consent state machine | No |
| [Picovoice Porcupine](https://github.com/Picovoice/porcupine) | Apache-2.0 (SDK); **proprietary** (engine, requires AccessKey) | On-device but phones home since v2.0 | No |
| [Pipecat](https://github.com/pipecat-ai/pipecat) | BSD-2-Clause | No consent model. Best barge-in support (<250ms) | No |

**What's unique:** (1) wake-word gate as consent boundary with explicit state
machine (armed → listening → processing → idle), (2) receipts record facts never
audio, (3) barge-in as state-machine event with consent implications.

**Component licences:** openWakeWord code Apache-2.0 (pretrained models
CC BY-NC-SA — custom-train to avoid), Silero VAD MIT, Faster Whisper MIT,
Kokoro TTS Apache-2.0.

**Verdict: Keep** (compose for components). The consent-boundary architecture
and receipt system have no external equivalent.

## 9. Safety machinery

### Friction floor (sycophancy detection)

Deterministic, model-free, lexicon-based scanner running outside the model it
watches. Detects when an agent mirrors the user while the user escalates.
"A mirror cannot audit itself."

| Alternative | Licence | Deterministic? | Runtime? | Sycophancy-specific? |
| --- | --- | --- | --- | --- |
| [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) | **Apache-2.0** | Mixed (Colang rules + LLM calls) | Yes | No built-in sycophancy detector |
| [Guardrails AI](https://github.com/guardrails-ai/guardrails) | **Apache-2.0** | Validator-dependent | Yes | No sycophancy validator in Hub |
| LLM Guard (Protect AI) | MIT | Scanner-dependent | Yes | No. **Archived July 2026** |
| AlignmentCheck (Meta) | MIT | No (few-shot LLM) | Yes | Goal hijacking, not sycophancy |
| Cascading Linear Features (research) | Paper | Requires white-box model access | Potentially | Yes, but not applicable to API models |

**Nothing else does deterministic runtime sycophancy detection without invoking
another LLM.** The research field has benchmarks (lechmazur, SycEval, ELEPHANT)
and mechanistic probes, but every runtime detector is LLM-as-judge — itself
susceptible to sycophancy.

**Verdict: Keep.** NeMo Guardrails (Apache-2.0) could host Friction Floor as a
custom Colang rail if a broader guardrails framework is needed, but the detection
logic has no external equivalent.

### External guard (indirect prompt injection)

Pattern-based scanner for prompt injection in fetched web content. Scans
response bodies before they enter agent context.

| Alternative | Licence | Scans tool responses? | Notes |
| --- | --- | --- | --- |
| [StackOne Defender](https://github.com/nichochar/defender) | **Apache-2.0** | **Yes** — built for it | Two-tier: pattern (~1ms) + classifier (~4ms), 22MB, CPU-only, 90.8% accuracy |
| [Rebuff](https://github.com/protectai/rebuff) | **Apache-2.0** | Input-focused | Heuristics + LLM + canary tokens |
| [prompt-armor](https://github.com/prompt-security/prompt-armor) | **Apache-2.0** | Input-focused | Shannon entropy, delimiter injection, offline |
| Lakera Guard | **Proprietary** (Check Point) | Yes | SaaS-only, not self-hostable |

StackOne Defender is the direct match — Apache-2.0, purpose-built for indirect
prompt injection in tool responses, lightweight.

**Verdict: Adapt.** Evaluate StackOne Defender as the detection engine; keep
willow-mcp's integration layer (scan-before-context-entry).

### Secret scan (egress credential redaction)

Scans every MCP tool response for leaked credentials and redacts before egress.

| Alternative | Licence | Scans what | Runtime? |
| --- | --- | --- | --- |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | **Apache-2.0** | Git commits/files, 27 detectors, plugin architecture | No (pre-commit/CI) |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | **AGPL-3.0** — excluded | Git repos, S3, Slack, 800+ secret types | No |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Git repos | No (pre-commit/CI) |
| [git-secrets](https://github.com/awslabs/git-secrets) | **Apache-2.0** | Git commits | No (git hooks) |

Every maintained scanner targets git history. None operates as an inline filter
on MCP tool responses. detect-secrets' 27 detector plugins could be extracted
and run against arbitrary strings with modest adaptation.

**Verdict: Compose.** Keep inline scanning architecture; adopt detect-secrets'
detector plugins (Apache-2.0) as the pattern library.

### Model egress consent gate

Verifies Ollama host resolves to loopback before allowing model calls without
`cloud_llm` consent.

No external tool verifies local-inference locality from the client side. The
2026 security literature documents the problem extensively but solutions are all
advisory (checklists, configuration guides) or infrastructural (firewalls).

**Verdict: Keep.** Simple, correct, novel, too small for an external dependency.

## 10. Privacy boundaries

### Exposure membrane

Per-destination slicing of agent persona data. Preset profiles: telemetry
(nothing), voice_only (register + voice rules), work_context (+ active work),
full_seed (everything).

The pattern is well-established (OAuth scopes, OIDC claims, ABAC). The
application to agent persona data is novel. OPA (Apache-2.0) could back the
policy rules if profile complexity grows, but four presets do not need a policy
engine.

**Verdict: Keep.**

### Nest content pipeline

Document ingestion with a mechanical wall: promotion carries structure but never
content, enforced in three places. Cheapest-tier-first classification cascade
(regex → local embeddings → local LLM). Self-learning centroid adaptation.

| Alternative | Licence | What it does | Comparison |
| --- | --- | --- | --- |
| [Unstructured](https://github.com/Unstructured-IO/unstructured) | **Apache-2.0** | Document extraction from 25+ formats | Extraction only; no classification cascade, no content wall |
| [Docling](https://github.com/DS4SD/docling) (IBM) | MIT | PDF/DOCX to structured output, layout-aware | Extraction only |
| [Apache Tika](https://tika.apache.org/) | **Apache-2.0** | Format detection + text extraction | Extraction only, heavier runtime |
| [Presidio](https://github.com/microsoft/presidio) | MIT | PII detection and anonymisation | PII audit layer; does not enforce a content/structure wall |

**Verdict: Compose.** Use Unstructured or Docling for extraction, Presidio for
PII audit. Keep the cheapest-tier-first cascade, the content/structure wall, and
the self-learning centroids — nothing external provides any of these.

## 11. Knowledge governance

### Mem-ratify (epistemic tier promotion)

Contested → Frontier → Canonical with independent-witness quorum and stepwise
enforcement. Pure stdlib, fail-closed, off-by-default enforcement.

No external software implements epistemic tier promotion as a mechanically
enforced gate. Wikidata statement ranks (Normal/Preferred/Deprecated) are the
closest shipped system but lack quorum and stepwise enforcement. Cochrane GRADE
is advisory, not fail-closed.

**Verdict: Keep.** Genuinely novel.

### Schema profile

Introspect database columns, propose semantic mapping with confidence tiers
(exact/alias/unmapped), require human confirmation before write tools activate.

| Alternative | Licence | What it does | Comparison |
| --- | --- | --- | --- |
| [OpenMetadata](https://github.com/open-metadata/OpenMetadata) | **Apache-2.0** | Metadata discovery, column profiling, lineage | Raw introspection; no semantic mapping with confidence tiers |
| [DataHub](https://github.com/datahub-project/datahub) | **Apache-2.0** | Metadata platform, schema discovery | Same gap |
| [Data Contract CLI](https://github.com/datacontract/datacontract-cli) | MIT | Schema contracts as reviewable artifacts | Format reference; no heuristic mapping |
| [Airbyte](https://github.com/airbytehq/airbyte) | MIT / Elv2 | Schema detection for source connectors | Detects schema, does not map meaning |

**Verdict: Compose.** Use OpenMetadata or DataHub for introspection. Keep the
semantic mapping with confidence tiers and the human gate — no surveyed tool
maps column meaning with graded confidence.

### MarkdownAI (mai)

Directive-based document format (`@markdownai v1.0`) with `@db`, `@http`,
`@env`, `@render`, `@if/@endif`, `@constraint`, `@define-concept`. A reactive
document engine executed within MCP.

No external system matches. MDX mixes React components into Markdown (different
paradigm). Observable notebooks are dataflow DAGs (different execution model).
Jupyter is a kernel-based notebook (not directive-based). Notion/Coda are
proprietary doc-database hybrids.

**Verdict: Keep.** Nothing to adopt or wrap.

## 12. Developer tooling

### Code graph

Python/JS call-graph indexer using stdlib `ast` + `sqlite3`. Token-budgeted
context walks, blast-radius analysis, fuzzy symbol search.

| Alternative | Licence | Notes |
| --- | --- | --- |
| [CodeGraph](https://github.com/nicholaschenai/codegraph) | MIT | 19 languages, MCP-native, benchmarked 35% cost reduction |
| [code-review-graph](https://github.com/nichochar/code-review-graph) | MIT | 24k stars, 25+ MCP tools, blast-radius analysis |
| tree-sitter | MIT | Multi-language AST parsing, 100+ grammars |
| Sourcegraph / SCIP | Apache-2.0 (SCIP) | Production code intelligence |

The agentic code-context space matured fast in 2026. Both CodeGraph and
code-review-graph are further along with MCP-native support.

**Verdict: Adapt.** Adopt tree-sitter for parsing breadth; wrap one of the
MCP-native graph tools rather than maintaining a parallel stdlib-only
implementation — unless zero-dependency is a hard constraint.

## 13. Operational infrastructure

### Commitment membrane

Calendar-backed commitment tracking with tamper-evident ledger. Three
disciplines: receipt-not-recording, states-not-deletions, no-new-authority.
A "dew rule" for surfacing.

Calendar AI tools (Clockwise, Reclaim.ai, Motion) are architecturally opposed —
they all create authority (schedule meetings, block time). Commitment-contract
tools (Beeminder, StickK) lack calendar backing and tamper evidence. No external
tool enforces the three disciplines.

**Verdict: Keep.**

### Human-in-the-loop primitives

Two-part system: (a) attention queue with priority and kind-based routing,
(b) durable attestation where `attested_by` is unforgeable. Plus a human-only
orchestrator seat that agents cannot assume.

| Alternative | Licence | Comparison |
| --- | --- | --- |
| [Temporal](https://github.com/temporalio/temporal) human tasks | MIT | Durable workflow with human steps; no attention queue or unforgeable attestation |
| [Netflix Conductor](https://github.com/Netflix/conductor) human tasks | **Apache-2.0** | Pause/resume with human-task states; no kind-based routing |
| [SPIFFE/SPIRE](https://github.com/spiffe/spire) | **Apache-2.0** | Could back unforgeable `attested_by` with X.509 SVIDs |

**Verdict: Compose.** Use SPIFFE for identity backing if attestation needs
asymmetric verification. Consider Conductor for durable orchestration. Keep the
attention queue and human-only seat — nothing provides kind-based routing with a
seat agents cannot assume.

### Forks (branch-scoped work tracking)

Branch as bounded work unit with append-only change log of atoms, tasks, threads,
and KB changes. SOIL-backed.

No external tool treats a branch this way. Changesets (MIT) is the closest
structural analogue but its domain is package versioning.

**Verdict: Keep.**

### Receipt log

Append-only, hash-chained SQLite audit trail recording every tool call
(ok/denied/rate_limited/error) with process-safe chaining and graduated
announcement volume.

| Alternative | Licence | Comparison |
| --- | --- | --- |
| [immudb](https://github.com/codenotary/immudb) | **Apache-2.0** | Merkle-tree verification; could strengthen tamper evidence |
| [Bifrost](https://github.com/bifrost-mcp/bifrost) | **Apache-2.0** | MCP-specific audit fields |
| [Trillian](https://github.com/google/trillian) | **Apache-2.0** | Certificate Transparency Merkle-tree log |

**Verdict: Compose.** Keep the embedded SQLite log with four-outcome model.
Study immudb for Merkle-tree verification to strengthen tamper evidence.

### Vault

Fernet-encrypted SQLite secret store with auto-generated keys at 0600
permissions.

Every Apache-compatible secret manager (Conjur, Infisical, OpenBao) requires
infrastructure willow-mcp should not acquire. The Fernet+SQLite design is
correct for a single-process server.

**Verdict: Keep.** Revisit if willow-mcp runs multi-instance.

### Gates panel / TUI

Live authorization-state dashboard across four output surfaces (static panel,
curses TUI, HTML, JSON API). Shows every gate with actionable rows.

Authorization tools (IAM Access Analyzer, OPA Playground) manage policies. The
Gates Panel visualizes live authorization state — different problem. The gate
taxonomy is domain-specific.

**Verdict: Keep.**

### Tree view (system health)

Single-call whole-system health aggregation using arboreal metaphors
(trunk/sap/canopy/roots/rings/leaves/litter/stomata). Degradation-aware.

Spring Boot Actuator (Apache-2.0) provides the best structural reference:
composite health indicators aggregating multiple subsystem checks with
status propagation.

**Verdict: Adapt.** Adopt Actuator's composite-health-indicator architecture as
the structural pattern. Keep the metaphor and single-call surface.

## 14. Subject consent

Per-verb-per-resource consent gating on MCP tool execution. Data subjects
(especially minors) have explicit consent records; guardian consent with
relationship verification; named-persons-only (L4) policy; fail-closed — tools
refuse when consent is absent. Withdrawal propagates to disable tool access.

| Alternative | Licence | What it does | Comparison |
| --- | --- | --- | --- |
| [Fides](https://github.com/ethyca/fides) | **Apache-2.0** | Privacy engineering: DSR fulfilment, consent propagation, fideslang taxonomy | Enforces consent in data pipelines, not at tool-call boundaries. No minor/guardian flows. Data-category scoping, not per-verb |
| Microsoft Consent-Package | MIT + CC-BY-SA-4.0 | Proxy/guardian consent, age-gating, granular scoping, revocation, audit trail | Closest consent *model*: has guardian consent for minors, per-category scoping, withdrawal. UI sample — advisory, not fail-closed |
| [OPA](https://github.com/open-policy-agent/opa) | **Apache-2.0** | General-purpose policy engine, fail-closed capable | Could *implement* consent-as-policy but ships no consent model — no subjects, no guardians, no withdrawal propagation |
| ScopeGate (alifanov) | MIT | Per-action OAuth scope restriction for AI agent tool calls | Gates tool calls (closest to fail-closed gating), but gates by *operator permission*, not *data-subject consent* |
| Kantara MVCR | Spec (CC) | Consent receipt JSON schema standard | Data model reference only. No enforcement. Implementations are stubs |

**What's unique:** No surveyed project combines all six properties: (1) consent
as a fail-closed runtime gate on tool execution, (2) guardian consent with
relationship verification, (3) named-persons-only subjects, (4) per-verb-per-
resource scoping, (5) withdrawal propagating to tool-call gates, (6) MCP-native.
ScopeGate gates tools by operator permissions; nothing gates them by data-subject
consent.

**Verdict: Compose.** Borrow Microsoft Consent-Package's consent model (MIT) as
design reference; use OPA (Apache-2.0) if consent predicate evaluation separates
from the server. The integration — data-subject consent driving fail-closed tool
gating with guardian verification — is novel. Build it.

## 15. Persistence and provenance

### SOIL (file-per-record persistence)

JSON file per record, directory per collection, app_id partitioning.
Schema-optional — validated at read, not write. Backs forks, gaps, receipts, KB
atoms, agent seeds.

| Alternative | Licence | What it does | Comparison |
| --- | --- | --- | --- |
| [TinyDB](https://github.com/msiemens/tinydb) | MIT | Pure Python document store, single JSON file | Single file, not file-per-record. No collection dirs, no app_id partitioning. Nearest Python equivalent |
| [LMDB](https://github.com/jnwatson/py-lmdb) | OpenLDAP (permissive) | Memory-mapped key-value store | Raw bytes, not JSON. No collection structure |
| [Dolt](https://github.com/dolthub/dolt) | **Apache-2.0** | MySQL-compatible DB with git semantics | Versioning is interesting but the shape is wrong — full relational DB, not file-per-record |
| [Irmin](https://github.com/mirage/irmin) | ISC | Git-principled distributed store, content-addressed | Closest in spirit — branchable, JSON-native. OCaml, not embeddable in Python |
| SQLite | Public domain | Embedded relational DB | The standard complement. Gains queries and ACID; loses git-diffable files and directory-as-collection |

**What's unique:** file-per-record + directory-as-collection + app_id
partitioning + validate-at-read. No surveyed tool replicates the three-axis
scoping (collection / app_id / record_id) as a filesystem layout. The pattern is
~200 lines; adopting a heavier tool trades clarity for features SOIL does not
need.

**Verdict: Keep.** SQLite is the right complement if queries are needed — already
used that way.

### Lineage (reasoning provenance)

Provenance chains where each record carries a reason/justification, not just what
changed but why. Records chain backwards through a decision history.

| Alternative | Licence | What it does | Comparison |
| --- | --- | --- | --- |
| [OpenLineage](https://github.com/OpenLineage/OpenLineage) | **Apache-2.0** | Standard for data-pipeline lineage: run/job/dataset events | Data-flow lineage (what moved where). No reasoning/justification field |
| [Marquez](https://github.com/MarquezProject/marquez) | **Apache-2.0** | Reference OpenLineage server, metadata service | Same limitation. Requires a running service |
| [W3C PROV (prov library)](https://github.com/trungdong/prov) | MIT | Python W3C PROV-DM: entity/activity/agent triples | Closest standard. Models who-did-what but "why" is not first-class — freeform attribute, not enforced or chained |
| [Apache Atlas](https://github.com/apache/atlas) | **Apache-2.0** | Enterprise metadata governance, Hadoop ecosystem | Data catalog lineage, not decision-trail provenance |

**What's unique:** records *reasoning* provenance — why a change was made — as a
required chained field, not data-flow lineage. Every surveyed tool tracks what
changed or what data flowed where. None enforces a chained reasoning trail. §1
already identifies `lineage_* with "why"` as one of eight shapes nobody else
builds; this survey confirms it.

**Verdict: Keep.** W3C PROV (MIT) is the export format if interop matters, but
the internal model — reasoning as a required, chained field — has no external
equivalent.

---

## Summary

Verdicts across all 22 surveyed systems:

| § | System | Verdict | Compose/Adapt with |
| --- | --- | --- | --- |
| 7 | Agent roles (8-layer auth) | **Keep** | Cerbos / OPA if policy grows; SPIFFE if federation |
| 8 | Voice ingress membrane | **Keep** | Components (openWakeWord, Silero, Whisper, Kokoro) |
| 9 | Friction floor | **Keep** | NeMo Guardrails as host framework if needed |
| 9 | External guard | **Adapt** | StackOne Defender (Apache-2.0) |
| 9 | Secret scan | **Compose** | detect-secrets detectors (Apache-2.0) |
| 9 | Model egress consent | **Keep** | — |
| 10 | Exposure membrane | **Keep** | OPA if profiles grow |
| 10 | Nest content pipeline | **Compose** | Unstructured / Docling + Presidio |
| 11 | Mem-ratify | **Keep** | — |
| 11 | Schema profile | **Compose** | OpenMetadata / DataHub |
| 11 | MarkdownAI | **Keep** | — |
| 12 | Code graph | **Adapt** | tree-sitter + CodeGraph / code-review-graph |
| 13 | Commitment membrane | **Keep** | — |
| 13 | HITL primitives | **Compose** | SPIFFE + Conductor |
| 13 | Forks | **Keep** | — |
| 13 | Receipt log | **Compose** | immudb for Merkle verification |
| 13 | Vault | **Keep** | — |
| 13 | Gates panel / TUI | **Keep** | — |
| 13 | Tree view | **Adapt** | Spring Boot Actuator architecture |
| 14 | Subject consent | **Compose** | OPA + MS Consent-Package model |
| 15 | SOIL persistence | **Keep** | — |
| 15 | Lineage (reasoning provenance) | **Keep** | W3C PROV as export format |

**Totals: 13 Keep · 3 Adapt · 6 Compose · 0 Adopt**

The recurring pattern: external tools provide plumbing (extraction, detection,
policy evaluation, identity). willow-mcp's contribution is the gate — the
enforcement layer that makes a guarantee mechanical rather than advisory. Nothing
surveyed replaces a gate; several could back one.

The zero in the Adopt column is not an oversight. §2 recommends adopting MCP
Resources and Streamable HTTP — protocol features, not system replacements. For
systems, every external tool is either plumbing to compose behind a gate, or an
architecture to adapt into willow-mcp's shape. No external system provides the
gate itself.
