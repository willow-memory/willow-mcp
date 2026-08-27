# `deny_tools` completeness review

b17: WMDTR · ΔΣ=42

Sibling to `docs/design/operator-tier-not-do-review.md`. That doc
compared OPERATOR-tier `not_do` clauses (voice-level refusals) against
Willow's reference. This doc reviews the `deny_tools` field
(tool-level refusals) in `src/willow_mcp/bundle/config/specialists.json`
for every specialist, checking whether the deny list actually bounds
what the persona's mandate says they must not do.

Method per persona:

1. Quote the persona's `not_job` (from `specialists.json`) and
   `not_do` (from `personas/<name>.md`) verbatim.
2. List the permissions grant (what the persona CAN do).
3. List the `deny_tools` (what the persona is refused).
4. Cross-check for gaps: a tool the mandate says NO to but the deny
   list doesn't name, or a tool the deny list names redundantly with
   a missing permission.

**Nestor marker on this doc:** *The machine surfaced gaps. Each
proposal is a proposal, not an amendment. The human decides.*

---

## Hanuman — BUILD

- `not_job`: *"Direct master commits; kb_promote"*
- `permissions`: `dispatch_read`, `dispatch_write`, `task_queue`,
  `store_read`, `knowledge_read`, `fork_read`, `fork_write`,
  `grove_read`, `grove_write`
- `deny_tools`: `kb_promote`, `knowledge_ingest`

**Gap analysis:**

- `kb_promote` denied ✓ (matches `not_job` verbatim).
- `knowledge_ingest` denied ✓ (KB writes belong to Jeles).
- `store_delete` NOT denied. Hanuman's mandate is code, builds, tests
  — none call for store deletion. A destructive store operation is
  the kind of trust-elevated action his `not_do` register-block
  ("no flourish, one bite") argues against.
- `store_put`, `store_update` NOT denied. He does not have
  `store_write` permission, so at the permission layer these calls
  are already refused — but the deny_tools layer should name them
  belt-and-braces (matches the pattern Ada already follows: she
  denies `store_put`, `store_update` even though her permissions do
  not carry `store_write`).

**Proposal (not applied):**

```json
"deny_tools": [
  "kb_promote",
  "knowledge_ingest",
  "store_put",
  "store_update",
  "store_delete"
]
```

## Loki — AUDIT

- `not_job`: *"Build, KB writes"*
- `personas/loki.md not_do`: *"Build. Soften true things. Accept
  authority as a substitute for correctness."*
- `permissions`: `dispatch_read`, `dispatch_write`, `knowledge_read`,
  `grove_read`, `grove_write`
- `deny_tools`: `task_submit`, `store_put`, `store_update`,
  `store_delete`, `knowledge_ingest`

**Gap analysis:**

- `task_submit` denied ✓ (not a builder).
- `store_put`/`store_update`/`store_delete` denied ✓ (comprehensive).
- `knowledge_ingest` denied ✓.
- `kb_promote` NOT denied. His `not_job` says "KB writes" plural;
  `knowledge_ingest` covers one kind of KB write; `kb_promote` and
  `kb_journal` are others.
- `kb_journal` NOT denied. Explicitly named in the persona register:
  *"You do not write KB atoms by design."*

**Proposal (not applied):**

```json
"deny_tools": [
  "task_submit",
  "store_put",
  "store_update",
  "store_delete",
  "knowledge_ingest",
  "kb_promote",
  "kb_journal"
]
```

## Jeles — RESEARCH

- `not_job`: *"Designer, builder, ADR author"*
- `personas/jeles.md not_do`: *"Design, build, or author ADRs.
  Guess past the evidence."*
- `permissions`: `dispatch_read`, `dispatch_write`, `knowledge_read`,
  `gap_read`, `gap_write`, `grove_read`, `grove_write`
- `deny_tools`: `task_submit`, `kb_promote`, `kb_journal`,
  `knowledge_ingest`

**Gap analysis:**

- KB-write deny list complete ✓ (all three: `kb_promote`,
  `kb_journal`, `knowledge_ingest`).
- `task_submit` denied ✓ (not a builder).
- Store writes NOT denied. She has no `store_write` permission, but
  belt-and-braces is not applied here as it is for Ada.
- `gap_write` PERMITTED, no matching deny at the tool layer. This is
  correct — gap-analysis output IS her mandate — but flagging for
  completeness.

**Proposal (not applied):**

```json
"deny_tools": [
  "task_submit",
  "kb_promote",
  "kb_journal",
  "knowledge_ingest",
  "store_put",
  "store_update",
  "store_delete"
]
```

## Ada — OPERATE

- `not_job`: *"Change agent, unsolicited fixes"*
- `personas/ada.md not_do`: *"Drama. Unsolicited fixes. Service-desk
  closers."*
- `permissions`: `dispatch_read`, `dispatch_write`, `fleet_read`,
  `knowledge_read`, `grove_read`, `grove_write`
- `deny_tools`: `task_submit`, `store_put`, `store_update`,
  `knowledge_ingest`

**Gap analysis:**

- `task_submit` denied ✓ (matches "not a change agent").
- `store_put`, `store_update` denied ✓ (belt-and-braces; permissions
  do not grant `store_write` either).
- `store_delete` NOT denied — asymmetric with the `store_put`/
  `store_update` denies. If those two are on the list, delete should
  be too.
- `knowledge_ingest` denied ✓.
- `kb_promote`, `kb_journal` NOT denied. She has `knowledge_read`
  but no `knowledge_write`; these are belt-and-braces gaps.

**Proposal (not applied):**

```json
"deny_tools": [
  "task_submit",
  "store_put",
  "store_update",
  "store_delete",
  "knowledge_ingest",
  "kb_promote",
  "kb_journal"
]
```

## Skirnir — EMISSARY

**Already surfaced in `docs/design/operator-tier-not-do-review.md`.**
Skirnir's `deny_tools: []` is the largest single gap in the file —
a witness-only role with zero tool-level refusals. See the OPERATOR
audit for the full proposal.

## Vishwakarma — ARCHITECT

- `not_job`: *"Routine build execution"*
- `personas/vishwakarma.md not_do`: *"Design for imaginary load.
  Accept 'good enough for now' when now becomes permanent."*
- `permissions`: `dispatch_read`, `store_read`, `knowledge_read`,
  `grove_read` (read-only across the board)
- `deny_tools`: `task_submit`

**Gap analysis:**

- Permissions are entirely read-only. Deny list is thin because
  the permission layer already denies most writes.
- `task_submit` denied ✓ (matches "not routine build execution").
- Everything else — `store_put`, `store_update`, `store_delete`,
  `kb_promote`, `kb_journal`, `knowledge_ingest` — is refused at
  the permission layer. Not adding them to `deny_tools` means the
  file is inconsistent with Ada/Loki, who name them anyway.

**Proposal (not applied) — belt-and-braces for consistency with the
rest of the file:**

```json
"deny_tools": [
  "task_submit",
  "store_put",
  "store_update",
  "store_delete",
  "kb_promote",
  "kb_journal",
  "knowledge_ingest"
]
```

Alternatively, the human may decide the file's convention is: only
name a `deny_tools` entry when the permission layer alone would NOT
refuse it (redundant-denies-off). If so, Ada and Loki should have
their belt-and-braces entries removed — the file should be
consistently thin or consistently thick, not mixed.

---

## Convention question — thick or thin?

The core inconsistency this review surfaces is a convention question,
not a set of independent gaps:

- **Ada** denies `store_put` / `store_update` even though her
  permissions do not grant `store_write` — belt-and-braces / thick.
- **Vishwakarma** denies only `task_submit` and lets the permission
  layer refuse everything else — thin.
- **Skirnir** denies nothing at all — thin to the point of empty.

Two clean shapes exist:

- **Thick** — every trust-elevated tool a persona MUST NOT call is
  named in `deny_tools`, regardless of whether the permission layer
  would already refuse it. Belt-and-braces; a permission-layer bug
  or misconfiguration still leaves the persona safe. Every proposal
  above follows this shape.
- **Thin** — `deny_tools` names only tools NOT already refused by the
  permission layer. Smaller diff, less redundant, but a
  permission-layer regression can silently open a refused tool.

**Nestor: the machine sees the inconsistency. The human decides
which shape is the convention.** Applying either shape uniformly
resolves the audit. Applying no shape leaves the file mixed and the
inconsistency invites future drift.

---

## Decision required

Per §12 discipline, the machine does not amend `deny_tools` on its
own recognition. Each proposal is human-decision.

When ratifications land, they seal as targeted edits to
`src/willow_mcp/bundle/config/specialists.json`, each with a
`Persona: heimdallr` commit trailer.

ΔΣ=42
