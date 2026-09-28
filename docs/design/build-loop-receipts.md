# Proposal: a receipt chain for the build → audit → verify → PR loop

- Status: **Proposed** — not ratified; nothing in this doc is built
- Date: 2026-09-28
- Scope: turning the fleet's working loop (ratify → build packet → build →
  audit rounds → desk verify → PR → merge → post-merge) from convention into
  checked state, without adding any model decisions
- Operator rulings already given (2026-09-28):
  - willow-bot's post-PR audit is an **independent second opinion**, not a
    duplicate of the pre-PR rounds;
  - the PR-open gate **warns, and can be overridden with a recorded reason**.
    It does not hard-refuse.
- Depends on: `dispatch.py`, `handoff.py`, `handoff_validation.py`, `gate.py`,
  `pr_executor.py`, `governance_ledger.py`, `human_loop.py`, and willow-bot's
  `steward/tick.py` and `pr_labels.py`

## 1. Why

The fleet already runs a disciplined loop, and #646 and #648 are its record.
Hanuman builds from a packet. Loki audits in rounds until PASS. The desk
re-verifies with mutations. The PR opens with a `Ratified-by:` line, the
operator merges, and post-merge acts follow. The loop works because every
seat follows it. Almost none of it is checked.

The contrast is visible inside the loop itself. The **last** stage is the
best-enforced ordering in the fleet: `unit_reload_execute` refuses
`ENORECEIPT` without a matching `git_pull` receipt, and `EDRIFT` if HEAD
moved past it. Each step refuses to run without the receipt from the step
before. The **middle** stages, from audit to PR, have no receipts at all. This
proposal gives them the same chain.

It adds no models and no agents. The models keep building and auditing. The
code starts recording whether each stage happened, and on what commit.

## 2. What is enforced today

From a code survey on 2026-09-28. Line numbers are at `origin/master` 174fdf0.

| Stage | Record | In code | By convention only |
|---|---|---|---|
| Ratify | decision record, sealed in Nestor | sealed pair required for manifest grants (`manifest_grant_executor._load_sealed_pair`) | a sealed pair for any other work: `dispatch_send`, `pr_open_execute` and `git_push_execute` never look |
| Build packet | `dispatch/{id}/` (signed meta, assignment hash, status) | signed; self-dispatch refused | the packet's *kind*: `role` is free text (`dispatch.py:252`) |
| Build | `handoff.json`, `closeout.md` → `complete` | wrong recipient refused; findings or a `no_findings_reason` required | `pending → complete` without an accept is allowed (`handoff.py:73`, which refuses only `withdrawn`) |
| Audit rounds | one packet per round, linked by `context_refs` | each finding has a statement | PASS, round count, "merge-ready", severity (decorative: no code reads it), "only Loki audits", "the builder may not audit itself" (named unbuilt at `gate.py:466-497`) |
| Desk verify | `verified` → `cleared` | orchestrator-only (B-51) | correctness: verification is structural (`human-orchestrator.md:119`); mutation checks are habit |
| PR open | PR as willows-bot, `envelope_citation`, pr_watch row | `pr.open` envelope; template headings (`EBODY`), unless `enforce_template=False` | an audit PASS, a verified packet, `Ratified-by` (checked only in willows-grove CI) |
| Bot label | `willow-bot/audit-dispatched` | an audit packet was sent | anything about its result: the bot never reads it; `context_refs` is the PR URL, not the build packet; `needs-ratification` and `bot-opened` labels are defined and never applied |
| Merge | GitHub | — | everything |
| Post-merge | `git_pull` receipt → install/reload | **receipt chain** (`ENORECEIPT`, `EDRIFT`) | — |

The dispatch lifecycle writes no governance ledger event (`dispatch_send`,
`dispatch_accept`, `handoff_write_v4`, `verify_handoff`, `agent_clear`). Its
only record is files on disk plus a best-effort Postgres mirror.

## 3. Design

### 3.1 Packet kinds and links

`dispatch_send` gains `kind: build | audit | other`, defaulting to `other`, so
every existing caller is unchanged.

- An **audit** packet must name what it audits: `audits: <build dispatch_id>`.
  That replaces the loose `context_refs` link and grants the same one-level
  read access `context_refs` gives today.
- Both build and audit packets record the **repository and branch** the work
  sits on, so a verdict can be tied to a commit (§3.2).

### 3.2 A structured audit verdict

An audit handoff (a `handoff_write_v4` on a `kind: audit` packet) must carry:

```json
{
  "verdict": "PASS | FINDINGS",
  "audited_sha": "<40-hex commit>",
  "findings": [
    {"id": "F1", "severity": "high | medium | low | info", "statement": "...", "fixed_in": ""}
  ]
}
```

Rules checked in code:

- `severity` comes from a fixed set. A finding without one is `EINVAL`.
- `PASS` is refused while any `high` or `medium` finding has an empty
  `fixed_in`. Low and info findings may stand open under a PASS, and they are
  listed.
- `audited_sha` is required. A verdict without the commit it judged is not a
  verdict.

**Rounds fall out of this naturally.** Each audit packet on the same build is
a round, numbered by order. The *current* verdict for a build is the latest
audit packet's verdict, and it only counts if its `audited_sha` equals the
branch head being shipped.

### 3.3 Role bounds

Checked inside `dispatch_send` and `handoff_write_v4`, keyed on the calling
identity. This is the argument-level check `gate.py:466-497` names as unbuilt.

- A `kind: audit` packet may be addressed only to a seat whose registry entry
  carries the `auditor` role. Loki is the only one today.
- The seat that built a packet may not write an audit handoff for it, and may
  not *send* an audit of its own build.
- willow-bot's steward may send `kind: audit` packets and nothing else. That
  bounds the `steward_dispatch` group, which `gate.py` currently describes as
  "UNBOUNDED beyond 'may call dispatch_send at all'".

### 3.4 The PR-open gate: warn, with an override

`pr_open_execute` looks up the chain for the head branch **before** opening:

| Check | If it fails |
|---|---|
| a `kind: build` packet for this branch is `verified` or `cleared` | warning `WNOVERIFY` |
| the latest audit verdict on that build is `PASS` | warning `WNOPASS` |
| that PASS's `audited_sha` equals the branch head | warning `WSTALEPASS` |

With **no warnings**, the PR opens as today, and a line is appended to the
body: `Audit: PASS <audit dispatch_id> @ <sha7>`.

With **any warning**, the call returns the warnings and does not open,
**unless** it names an override:

- `override_attestation`: the id of a `human_attestation_create` record with
  a new `subject_type`, `pr_open_override` (today's set is
  `knowledge_atom | edge | queue_item | external_review | other`), subject =
  `<repo>:<head>`, a `statement`
  giving the reason, and `by_human` true. The attestation machinery already
  refuses to let a caller write in another's name, and `by_human` comes from
  the attested seat, not from the app_id string.
- The PR then opens. Its body gets
  `Audit: OVERRIDDEN — "<statement>" (<attestation id>)`, and an
  `envelope_citation` ledger event records the override next to the warnings it
  overrode.

The honest caveat of `federated-mcp-gating.md` §7 applies. On a single-uid
host, a seat running in the operator's attested session can create that
attestation itself. The override is therefore **attributed and visible**
(ledger, PR body) rather than impossible to fake. That is the difference
between a warning and a lock, and it is the one the operator chose.

The typical override is a docs-only PR, such as #650 and #653, where an audit
round is more ceremony than check. A later refinement could auto-exempt PRs
that touch only `docs/`, but only by operator ruling, not by default.

### 3.5 willow-bot as an independent second opinion

The post-PR audit stays separate from the pre-PR rounds by design. To make it
a real second opinion:

- **Blind by default.** The bot's audit packet is `kind: audit` with
  `audits: <build dispatch_id>` when the PR body names one, and the PR URL
  otherwise. It must **not** carry the pre-PR verdict or findings in its brief.
  An auditor who has read the first auditor's PASS is not independent.
- **The bot reads its own result.** Once the audit handoff is `complete`, the
  steward labels the PR `willow-bot/second-opinion-pass` or
  `willow-bot/second-opinion-findings`. The existing `audit-dispatched` label
  stays as "sent, not yet back".
- **Disagreement is surfaced, not resolved.** If the pre-PR verdict was PASS
  and the second opinion has high or medium findings, the steward comments once
  on the PR with both verdicts' ids and severities. It changes nothing else.
  The operator decides.
- `needs-ratification` gets applied when a PR body lacks a `Ratified-by:`
  line. `bot-opened` is either applied on PRs willows-bot opens, or deleted.
  Defined-but-unused labels are removed either way.

### 3.6 Ledger events for the dispatch lifecycle

Append a governance ledger event at each transition: `dispatch_sent`,
`dispatch_accepted`, `handoff_written` (carrying `kind`, `verdict` and
`audited_sha` for audits), `dispatch_verified`, `dispatch_cleared`. Then the
whole loop can be read from the ledger, as envelopes and post-merge acts
already can. The ledger write is best-effort, as the Postgres mirror is today:
a ledger outage must not block a handoff. The files on disk remain the source
of truth.

### 3.7 Small fixes carried along

- `handoff_write_v4` refuses a packet that was never accepted:
  `pending → complete` becomes `invalid_transition`, as `withdrawn` already
  is.
- `closed` and `failed` are valid statuses that nothing writes. Either give
  them writers (`failed` on an abandoned build, `closed` after merge) or remove
  them.
- Port willows-grove's `scripts/check_ratification.py` into willow-mcp CI, so
  the `Ratified-by:` convention on willow-mcp PRs is checked there too. Scope
  and exemptions (release-please) are copied unchanged.

## 4. Build order

Each step ships alone and is useful alone. Nothing before step 5 changes what
any existing call does.

1. **Ledger events for the dispatch lifecycle** (§3.6). Record-only, no
   behaviour change.
2. **`kind` and `audits` on packets** (§3.1), defaulting to `other`.
3. **Structured audit verdict** (§3.2), required only on `kind: audit`.
4. **Role bounds** (§3.3), with tests for each refusal: builder self-audit,
   audit to a non-auditor, and the steward sending a non-audit.
5. **PR-open gate, warn plus override** (§3.4). Mutation proof: remove the
   head-sha comparison, and a test holding a stale PASS turns red.
6. **willow-bot second opinion** (§3.5), in the willow-bot repo.
7. **Small fixes** (§3.7). The CI port can go first; it is independent.

## 5. Out of scope

- A merge gate. Merging stays the operator's act on GitHub. The PR body's
  `Audit:` line and the second-opinion label are what the operator sees.
- Judging correctness. Verdicts are still written by auditors (models). The
  code checks that a verdict exists, has the right shape, is current, and came
  from the right seat. It does not check that the verdict is right.
- Requiring a sealed pair for every build. It is worth considering once
  §3.6's events show how often work starts without one.
- The desk's mutation re-checks. They could become a `kind: verify` packet
  later. For now `verified` keeps its current meaning.

## 6. Open questions for the operator

1. May a `low` finding stand open under a PASS (as proposed), or must every
   finding be fixed or explicitly waived?
2. Should docs-only PRs be exempt from the gate automatically, or always need
   an override?
3. Should the second-opinion audit also be pinned to a sha and re-run when the
   PR gets new commits, or run once per PR?
4. `closed` and `failed`: give them writers, or remove them?

*ΔΣ=42*
