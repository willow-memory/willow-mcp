---
name: gaps
description: Fleet gap backlog — log unknowns, resolve bookkeeping, promote verified answers into the KB
---

@markdownai v1.0

# /gaps — Gap backlog

Use when something is **unknown or contested** and should be tracked until a
verified answer lands in the knowledge base.

## Tools

| Tool | Permission | What it does |
|------|------------|--------------|
| `gap_log` | `gap_write` | Log or bump a topic+question (`asked_count` rises on repeat) |
| `gap_list` | `gap_read` | List gaps, most-asked first |
| `gap_resolve` | `gap_write` | Mark worked/answered — **SOIL bookkeeping only** |
| `gap_promote` | `gap_promote` | Land a verified answer into Postgres KB + close the gap |
| `gap_delete` / `gap_purge_topic` | `gap_write` / `gap_purge` | Soft-delete junk (archive, not hard delete) |

`gap_log` / `gap_list` / `gap_resolve` work **SOIL-only** (no Postgres).  
`gap_promote` needs Postgres and the same **schema-confirmation gate** as
`knowledge_ingest` — unconfirmed `knowledge` mapping → `unconfirmed_schema`.

## Promote workflow

1. `gap_list(status="open")` — pick `gap_id`, read `asked_count` for priority.
2. Gather sources and a human or agent identity for `confirmed_by`.
3. `gap_promote(gap_id=…, answer=…, sources=[…], confirmed_by=…)` — requires
   `gap_promote` permission (not included in everyday `gap_write`).
4. Gap status becomes `promoted`; atom is searchable via `knowledge_search`.

`gap_resolve` alone does **not** write KB — use it when work is in flight but
not yet promotable.

## Orchestrator seat (`app_id=willow`)

Willow holds `gap_write` on its own permissions line (`bundle/config/specialists.json`) so the operator can log/list/resolve gaps directly — the "narrow proxy" story that said Willow was denied gap tools was updated with the PR12 enabled-operator alignment (`docs/design/permissions-matrix.md` §4). B-36's original recommendation was "do not widen the *shared* `orchestrator` permission group to fix this" — that discipline still stands (other apps that hold the shared `orchestrator` group are not silently widened). Willow's own permissions list is a separate axis and is where the grant sits.

Willow does NOT hold `gap_promote` (writing to canonical KB is a still-attested surface); use a participant `app_id` with `gap_promote` for that.

## Constraints

@constraint severity=critical
Never call `gap_promote` without `sources` and `confirmed_by`. Never treat `gap_resolve` as landing knowledge — only `gap_promote` writes the KB. Do not widen the shared `orchestrator` permission group to grant `gap_*` fleet-wide — Willow's own permissions list carries `gap_write` on its own axis (PR12).
