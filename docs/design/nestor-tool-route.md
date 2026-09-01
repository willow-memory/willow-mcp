---
kind: doc
name: nestor-tool-route
description: "A natural-language → willow-mcp tool router built on Nestor's verified-match engine. Fail-closed (serve a sealed phrasing or queue it for a human — never guess), backed by a signed, integrity-checked catalog bundle. Sketched 2026-08-11."
---

@markdownai v1.0

# Nestor tool route

*Status: **PROPOSAL** — sketched 2026-08-11, no code yet. Depends on the optional
`nestor` engine (unpublished git dep; see the oakenscrolls soft-seam pattern).*

*Companion: `friction-floor` · `lineage.py` · `receipts.py` ·
`governance_ledger.py` · `permissions-matrix.md`*

@define-concept sealed pair: A human-verified `surface → canonical` mapping in
Nestor's memory, HMAC-signed and recorded in a hash-chained ledger. Only a
sealed pair whose match clears the seal threshold may be *served*.

@define-concept the oracle: The willow-tool instance of Nestor — its domain is
`tool`, its canonicals are willow-mcp verb names, and its surfaces are the
natural-language phrasings humans have sanctioned for each.

## The gap

willow-mcp exposes 152 tools. An agent (or a human at a prompt) that knows
*what it wants* — "show me what breaks if I touch this file" — still has to know
that the verb is `code_graph_impact`. Fuzzy self-discovery today is either the
model guessing from tool names, or a keyword grep. Both fail the willow way:
**a confidently-wrong tool choice is worse than "I don't know yet"**, and neither
leaves a trail.

Nestor already solves exactly this shape of problem — resolve a fuzzy *surface*
to a verified *canonical*, serve only above a threshold, queue the rest for a
human — for translation memory, entity aliases, and (in oakenscrolls) almanac
citations. It has never been pointed at a **tool catalog**. This is that.

## The thesis: fail-closed routing

`nestor_tool_route(query)` returns **exactly one** of:

- **served** — a human sealed this phrasing (or one lexically within threshold);
  the resolved `tool` is returned with its confidence.
- **queued** — no sealed phrasing clears the bar; the intent is logged for a
  human to seal. No tool is returned. *This is the default, not the failure.*
- **unavailable** — the optional Nestor engine isn't installed.

It **never guesses**. In a live sketch run, `"verify the tamper evident chain
please"` scored 0.90 against the sealed `"verify the tamper evident chain"` and
was **refused** (threshold 0.92) rather than served `frank_verify` on a near
miss. For a router that can invoke real, sometimes-destructive verbs, that
refusal is the feature.

## The teach-loop

```
route(query) ──served──▶ tool
      │
      └─queued──▶ nestor_tool_pending ──▶ human ──▶ nestor_tool_seal ──▶ (next route serves)
```

The queue is not exhaust — it is the training signal. willow learns its own
vocabulary over time, one human-sanctioned phrasing at a time. Every routed
intent, served or queued, appends a passage to a hash-chained ledger, so the
oracle's answers are auditable like any other served answer in the fleet.

## The verbs

| verb | posture | ACL group |
|---|---|---|
| `nestor_tool_route(app_id, query)` | serves or queues; persists a ledger passage + queue entry | `tool_oracle_route` (write-capable, broadly grantable) |
| `nestor_tool_seal(app_id, surface, tool)` | **governance write** — sanctions a phrasing→verb | `tool_oracle_seal` (human / attested only) |
| `nestor_tool_pending(app_id, limit)` | pure read; the unsealed teach-queue | `tool_oracle_read` |

`nestor_tool_seal` grants a phrasing the power to invoke a real verb. It MUST be
gated to human or attested seats (`human_attestation_*`) — otherwise an agent
could seal `"clean up" → store_purge_collection` and then invoke it through the
front door it just built. The `verifier` recorded on the seal is the sealing
identity.

## The catalog ships as a signed bundle

The oracle is seeded from a Nestor **portable bundle** (`export_bundle`) checked
into the package: `willow_mcp/bundle/tool_oracle.bundle.json`. Each row carries a
`seal_sig` HMAC and the bundle carries a content `digest`. On first use the
module runs `verify_bundle` **before trusting it** and **fails closed** if the
catalog was tampered — a single redirected target (`frank_verify → frank_disable`)
changes the digest and the load is refused. The oracle is trustworthy because it
is *checkable*, not because the file asserts it.

A fleet may override the shipped catalog (`WILLOW_TOOL_ORACLE_BUNDLE`) or start
empty and teach the oracle live.

## Where state lives

Vault-rooted, gitignored, per-fleet — never in the repo:

- `$WILLOW_HOME/store/tool-oracle/oracle.db` — the Nestor SqliteStore (domain `tool`).
- `$WILLOW_HOME/store/tool-oracle/ledger.jsonl` — the hash-chained passage ledger.

Consistent with `receipts.py` / `governance_ledger.py`: served answers leave a
trail; the ledger is verifiable.

## Nestor stays optional

Imported lazily behind a cached `_nestor()` seam (the exact pattern merged for
oakenscrolls' `almanac_seam`). Absent the engine, the verbs return
`{"status": "unavailable", ...}` — never an `ImportError` at server import. Nestor
is installed directly from git (`pip install "nestor @
git+https://github.com/Die-Namic-Systems/Nestor@master"`); it briefly lived in a
`[nestor]` optional extra, but PyPI refuses any package whose metadata carries a
direct URL dependency, and that extra blocked the v2.8.0–v2.9.1 uploads (see
pyproject.toml's note). `pip install willow-mcp` stands up the server without it.

## Decisions & rationale

| decision | why |
|---|---|
| serve-or-queue, never guess | a wrong verb is worse than a deferral; matches the gate ethos |
| `seal` is human-gated | sealing mints invocation power for a phrasing |
| verify bundle on load | a tampered catalog must not silently reroute a verb |
| lazy/optional Nestor | server must import and run without the engine |
| vault-rooted + ledgered | answers are auditable; no repo-side state |
| lexical matcher first | `StringMatcher` is offline/stdlib; semantic lift is future work |

## Known limits & future work

- **Lexical, not semantic.** `StringMatcher` (difflib) serves near-verbatim and
  queues true paraphrases (`"what would break if I edit this"` → queued, not
  `code_graph_impact`). Nestor's `semantic_matcher` / `embedding_store` would lift
  these, but needs an embedding backend (e.g. ollama) — out of scope for the
  offline default. The domain's matcher is recorded in the bundle envelope, so a
  semantic upgrade is a domain re-key, not a silent behavior change.
- **Catalog drift.** When a verb is renamed/removed, its sealed pairs point at a
  dead canonical. A `tool_oracle_lint` check (canonical ∈ live tool registry)
  should run in CI against the shipped bundle.
- **Per-manifest scoping.** v1 routes against the whole catalog; a later cut
  could intersect results with the caller's resolved tool set so `route` only
  ever surfaces verbs the caller may actually invoke.

## Test plan

- `route` served / queued / unavailable paths (Nestor present and blocked, via
  the meta-path-finder pattern from oakenscrolls' degraded-path test).
- Tampered-bundle-refused: flip a target, assert `_ensure_seeded` fails closed.
- `seal` → `route` round-trip: a queued phrasing serves after sealing.
- Gate: `nestor_tool_seal` denied for a non-human/unattested seat.
