---
kind: doc
name: nestor-propose-bridge
description: "The missing in-process step between recording a governance decision in SOIL and a human sealing it in Nestor — decision_propose lands a draft and stamps the correlation key so seal_handler.on_seal can find it again. Built 2026-09-11."
---

@markdownai v1.0

# Nestor propose bridge

*Status: **SHIPPED** — `decision_bridge.propose` / the `decision_propose` MCP
verb, 2026-09-11.*

*Companion: `seal_handler.py` (the consumer half — what happens when a seal is
seen) · `seal_daemon.py` (tails the ledger) · `tool_oracle.py` (the same
soft-Nestor-seam pattern, applied to a different domain)*

@define-concept draft: An unsigned `question -> commitment` pair in Nestor's
own database, produced by `DecisionMemory.propose`. A machine may create one;
it is never served as verified.

@define-concept the correlation key: `nestor_pair_id` on a SOIL governance
record. `seal_handler.on_seal` finds the record to upgrade by scanning
`projects_willow_governance_decisions` for `nestor_pair_id == <sealed
pair_id>` — nothing else ties a SOIL record to a Nestor row.

## The gap this closes

A governance decision is recorded in SOIL today with `store_put` into
`projects_willow_governance_decisions`. Separately, `seal_handler.on_seal`
already knows how to *upgrade* that record to `status: "sealed"` when it sees
a matching seal on the Nestor ledger — but only if the record already carries
a `nestor_pair_id` equal to the ledger's `pair_id`.

Until this bridge, there was no in-process or MCP path to get a draft into
Nestor at all: the only way was shelling out to Nestor's own venv by hand,
outside any tool the fleet's gate/receipt/rate-limit pipeline ever sees. And
doing it by hand never wrote `nestor_pair_id` back onto the SOIL record —
so a decision recorded via `store_put` and a draft proposed separately never
correlated. A human could seal the draft in Nestor all day and
`seal_handler.on_seal` would return `"unmatched"` forever: the seal loop
looked closed but silently upgraded nothing.

## The lifecycle

```
store_put                    (record the decision in SOIL, status: "proposed")
    │
    ▼
decision_propose              (this bridge: land a DRAFT in Nestor,
    │                          stamp nestor_pair_id on the SOIL record)
    │
    ▼
a human seals the draft        (in Nestor, with their own signing key —
    in Nestor, out of band       out of reach of this bridge or any MCP tool)
    │
    ▼
seal_daemon tails the ledger,  (willow-ratatosk's SeatDaemon +
calls seal_handler.on_seal      JsonlTailWatcher, at-least-once delivery)
    │
    ▼
on_seal scans for               (the correlation decision_propose just
nestor_pair_id == pair_id,       made possible — the record is now
upgrades the SOIL record         findable by the pair_id the seal names)
to status: "sealed"
```

`decision_propose(app_id, record_id, question="", conclusion="",
rationale="", origin="")`:

1. Loads the SOIL record `record_id` from
   `projects_willow_governance_decisions`. Missing → `{"error":
   "record_not_found"}`.
2. **Idempotent.** If the record already carries a non-empty
   `nestor_pair_id`, it is not proposed again —
   `{"pair_id": <existing>, "record_id": record_id, "status":
   "already_linked"}`. A retried call (or a second operator re-running the
   same step) must never mint a second draft for the same decision.
3. Lazily imports `nestor`; absent the optional `nestor` extra, degrades to
   `{"error": "nestor_unavailable"}` — the same soft-seam discipline
   `tool_oracle.py` uses, never an import crash.
4. Resolves the vault's `nestor.db` via `seal_handler._nestor_db_path()`
   (reused, not reinvented — `WILLOW_NESTOR_DB` env or
   `paths.willow_home()/"nestor.db"`), builds
   `DecisionMemory(SqliteStore(db), domain="decision")`, and calls
   `.propose(question, conclusion, rationale=rationale, origin=origin)`.
   `question`/`conclusion`/`rationale`/`origin` default from the SOIL
   record's `title`/`ruling`/`rationale` (and a `willow:<app_id>:<record_id>`
   origin) when the argument is left blank; an explicit argument always
   overrides.
5. Stamps `nestor_pair_id` on the SOIL record with the new draft's id — the
   correlation `on_seal` needs — via `store.update`.
6. Returns `{"pair_id": pair_id, "record_id": record_id, "status": "draft"}`.

## `DecisionMemory.propose`'s actual return shape

`nestor.decision.DecisionMemory.propose(question, commitment, rationale="",
origin="")` (note: the parameter is named `commitment`, not `conclusion` —
this bridge's own signature keeps `conclusion` as the public arg name since
that reads better against a governance *ruling*, and passes it through
positionally) delegates to `nestor.memory.add_pair(...)`, which returns the
**full pair row**, not a bare id. The key this bridge relies on is `id`
(**not** `pair_id`) — `{"id", "source_text", "source_norm", "source_lang",
"target_text", "target_lang", "status", "verifier", "weight", "origin",
"reason", "created_at", "seal_sig"}`. `id` is what later shows up as
`pair_id` on the seal ledger record once a human seals it
(`nestor.memory._log_seal_event` writes `{"pair_id": pair["id"], ...}`) — the
same value, two different field names depending which side of the seal
you're reading it from.

## Why propose != seal keeps the sudo invariant

`DecisionMemory.propose` is documented in `nestor/decision.py` as "the one
write a model may make; it confirms nothing" — it lands an unsigned draft.
`DecisionMemory.seal` is a different method entirely, and it requires a
`seal_sig` produced by the verifier's own signing key; nothing in this
process can produce one. `decision_propose` calls only `.propose`, never
`.seal` — so no matter what a caller passes in, this bridge cannot ratify its
own draft. The human-seals-in-Nestor step in the lifecycle above is not a
convention this bridge is trusting a caller to follow; it is the only path
that exists, because the signing key this bridge would need to skip it never
touches this process. Same shape as `nestor_tool_seal` vs `nestor_tool_route`
in `tool_oracle.py`, and the same reason `governance_propose` (this tool's
gate group) is kept separate from `full_access`: the tool only ever touches
`projects_willow_governance_decisions`, and even holding it grants no power
to seal anything.

## Files

- `src/willow_mcp/decision_bridge.py` — `propose()`, the soft Nestor seam.
- `src/willow_mcp/server.py` — the `decision_propose` MCP verb
  (`@_guarded`, `_ANNO_WRITE`).
- `src/willow_mcp/gate.py` — the `governance_propose` permission group.
- `tests/test_decision_bridge.py` — unit tests plus the end-to-end
  `test_propose_then_seal_closes_the_loop`, which proves the whole point:
  `decision_propose` followed by a synthesized seal record through
  `seal_handler.on_seal` now upgrades the SOIL record, where before this
  bridge it would have returned `"unmatched"` forever.
