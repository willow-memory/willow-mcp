# The Nest — personal-file content pipeline

> *"Dump your life and let the pigeon figure it out."*

The Nest is a content pipeline for a folder of personal files. Point it at a
drop folder; it walks the tree, extracts text (OCR / PDF / docx / plaintext),
classifies each file's fragments **by meaning**, and writes a canonical SQLite
Nest DB. That DB — a person's legal filings, journals, receipts, messages — is
the **local PII zone**. From it, the Nest promotes *structure* (not content)
into the shared knowledge base.

The engine (`willow_mcp.nest`) grew out of
[`rudi193-cmd/safe-app-store` `apps/nest-seed`](https://github.com/rudi193-cmd/safe-app-store)
(MIT) and was vendored from its `libs/nest-pipeline` until 2026-09-12; its home
is this repo now (safe-app-store is archived and is never an origin again —
owner decision). Both halves ship: the **content pipeline** (`nest_scan`/`status`/`digest`/`promote`,
below) and the **live drop-folder router** (scan → human-gate → file-move, the
`nest_intake_*` tools — see [The live drop-folder router](#the-live-drop-folder-router)).

## The tools

All four are gated by the manifest ACL (`gate.py`): `nest_read` grants the
read tools, `nest_write` the writes. All run through `_guarded`, so egress
secret redaction and receipts apply to every result.

| Tool | Group | Does |
|------|-------|------|
| `nest_scan` | `nest_write` | Walk a folder → extract → classify → write a SQLite Nest DB. Returns counts. `dry_run=True` (default) reports without writing. |
| `nest_status` | `nest_read` | Sources by status, fragments by type, topical categories by size. |
| `nest_digest` | `nest_read` | A one-page Markdown map — the **walled** view. |
| `nest_promote` | `nest_write` | Promote the Nest's **structure** into the KB (`_knowledge_ingest_core`). `dry_run=True` returns the atoms that would be promoted. |

```
nest_scan  ──►  SQLite Nest DB  ──►  nest_status / nest_digest  (read it back)
 (drop folder)   (local PII zone)          │
                                            └─►  nest_promote  ──►  knowledge base
                                                 (structure only, walled)
```

Classification is a cheapest-tier-first cascade: **regex** facts → local
**embedding** centroids (Ollama `nomic-embed-text`) → a local **LLM** on the
uncertain tail (`--llm`). Every tier degrades gracefully when its model is
absent, falling back to regex. No cloud inference; nothing leaves the machine.

Optional source-type support (OCR / PDF / docx) installs with
`pip install willow-mcp[nest]` plus system `tesseract-ocr` and `poppler-utils`.
The base install stays dependency-free.

## The wall

The Nest DB holds raw content. The promotion path must not carry it into the
shared KB. The guarantee — the same seam corpus-lens's Guard enforces:

> **Relative/structural shape is process — shareable. Absolute content — a
> name, a date, a filename — is person — walled.**

Enforced mechanically, in three places:

1. **`nest_promote` can only reach `bridge.build_bridge`**, which selects
   **counts + curated category names + redacted secret *kinds*** — never a
   fragment's content. It is structurally incapable of ingesting content.
2. **A category allowlist.** A fragment's `label` is a real topical category
   only when the embedding/LLM tier classified it; the regex fallback labels a
   document/receipt with its **filename** (which embeds dates and names). Only
   allowlisted category names (`legal`, `journal`, `financial`, … or a curated
   `auto:` cluster) cross the wall — a filename never does. Dropped fragments
   are **counted as `uncategorised`**, honestly, not silently hidden.
   (`nest_status`, `nest_digest`, and `nest_promote` all apply this filter.)
3. **`nest_digest` returns the walled view over MCP.** Person names, the date
   timeline, and source filenames are suppressed; the full unwalled digest is a
   local-CLI affordance only.

Plus the standing `_guarded` backstop: every tool result is passed through
`secret_scan.redact_egress`, so a stray credential in any Nest output is
redacted and receipted before it leaves.

`tests/test_nest.py` holds the wall to these claims — including the load-bearing
`test_bridge_emits_no_content_names_or_filenames` and the
`test_bridge_drops_filename_labels` regression.

## The live drop-folder router

*"The pigeon sorts your desktop."* The second half of the Nest: a router that
watches a drop folder, classifies each new file **by filename** into a *track*,
and — on an explicit human gate action — moves it into place.

| Tool | Group | Does |
|------|-------|------|
| `nest_intake_scan` | `nest_write` | Classify new files in the drop zone into tracks and **stage** a queue. Idempotent, non-destructive. |
| `nest_intake_queue` | `nest_read` | List the pending queue with each file's predicted track. |
| `nest_intake_file` | `nest_write` | **Move** the file to its track's destination (or `override_dest`). |
| `nest_intake_skip` | `nest_write` | Leave the file; record the skip. |
| `nest_intake_flags` | `nest_read` | Open rule-delta flags the classifier has proposed. |

```
drop folder ──► nest_intake_scan ──► review queue ──► nest_intake_file ──► ~/personal/<track>/
 (~/Desktop/Nest)  (classify by name)   (nest_intake_queue)   (confirm / override / skip)
                                                                      │
                                                    override ─────────┘
                                                    (correction counter → flag at threshold)
```

**Nothing moves without a confirm.** `nest_intake_scan` only stages; a file is
moved only by an explicit `nest_intake_file` call naming the item. This is an
**owner == subject, single-operator** surface: the queue names the operator's
own files so they can decide, and that state lives in the local SOIL store — it
is *not* promoted to any shared KB (that is `nest_promote`'s job, and it is
walled). Filing moves files on the host, so `nest_intake_file` sits in
`nest_write` and is subject to the same tier ceiling as any write.

### The feedback edge — the classifier proposes, the human ratifies

Every gate action records the classifier's **prediction** and the human
**outcome**. When they differ (you filed it somewhere other than predicted), a
correction counter keyed by `(predicted → outcome, extension)` increments; at
`CORRECTION_FLAG_THRESHOLD` (3) a **flag** opens (`nest_intake_flags`) proposing
a keyword/rule delta. The classifier **never rewrites its own rules** — the flag
describes the delta; a human ratifies it by editing `$WILLOW_HOME/nest_rules.json`
and bumping its version. This is the learning loop corpus-lens's static
classifiers lack, kept honest by a human in the ratification seat.

### The rules seed is generic — on purpose

`rules.py` classifies by filename using `rules.seed.json`, a **PII-free** generic
template. The willow-2.0 seed this was adapted from had leaked the operator's
private keywords (case numbers, medical/legal matters, personal names); shipping
those in a packaged engine would be the exact wall breach this project forbids.
The operator's real ruleset lives only in their local `$WILLOW_HOME/nest_rules.json`
(materialized from the seed on first use, then theirs to edit), never in the package.

## What is out of scope (by design)

- **Owner ≠ subject.** A life dump contains people who are not its owner — a
  co-parent, a child. The Nest classifies them into `person` fragments locally;
  the wall keeps those out of the shared KB, but the deeper consent question
  (may their data be here at all?) is unsolved here, as it is in corpus-lens.
