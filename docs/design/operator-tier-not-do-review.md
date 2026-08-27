# Operator-tier `not_do` review

b17: WMOTR · ΔΣ=42

Grove v0.9 sealed `docs/INVARIANTS.md §12` (Ratification) in
`rudi193-cmd/safe-app-willow-grove`. §12 says: PR-open, merge, and
master-push are refused without a recorded human authorization; no
fleet persona has unilateral authority — not even Willow, whose own
`not_do` line explicitly forbids acting without a ratification.

This document audits the two willow-mcp resident OPERATOR-tier
personas — **Ada** and **Skirnir** — against Willow's reference
`not_do`, to find gaps where they carry higher permissions than their
mandate cleanly bounds.

**Nestor marker on this doc:** *The machine surfaced the gaps. The
human decides whether each gap is an alignment target or a documented
divergence — proposals below are proposals, not amendments.*

---

## Willow — the reference

From `personas/willow.md`, `not_do` clause verbatim:

> **What you do not do:** Commit, PR, merge, patch, or wire the fleet
> without a recorded authorization — finding a gap is not permission
> to close it. Read discussion as authorization. Write outside the
> active tree. Cushion "not recorded."

Five refused actions plus two attestation-failure modes plus one
scope constraint.

## Ada — Keeper of the Quiet Uptime

From `personas/ada.md`, `not_do` clause verbatim:

> **What you do not do:** Drama. Unsolicited fixes. Service-desk
> closers.

**Distance from Willow's clause:**

| Willow refuses | Ada refuses |
|---|---|
| Commit without ratification | (not named) |
| PR without ratification | (not named) |
| Merge without ratification | (not named) |
| Patch without ratification | *"unsolicited fixes"* — thematically covers this |
| Wire the fleet without ratification | (not named) |
| Read discussion as authorization | (not named) |
| Write outside the active tree | (not named) |
| Cushion "not recorded" | (not named) |

Ada's `permissions` in `specialists.json`: `dispatch_read`,
`dispatch_write`, `fleet_read`, `knowledge_read`, `grove_read`,
`grove_write`. She can dispatch to the fleet and write to Grove — both
are trust-elevated actions Willow's clause guards.

**Machine-surfaced observation:** Ada's clause covers *behavioral*
refusals ("drama", "closers") and one action-shaped one ("unsolicited
fixes"). It does not name commit/PR/merge/wire as forbidden without
authorization, but her `permissions` allow those adjacent actions.

**Proposal (not applied):** Extend Ada's `not_do` to explicitly refuse
`dispatch` and `grove_write` without a recorded incident ticket or a
Willow-scoped authorization. Rewording sketch:

> **What you do not do:** Drama. Unsolicited fixes. Service-desk
> closers. Dispatch or write to Grove without a recorded incident
> ticket or Willow-scoped authorization — finding a monitoring gap
> is not permission to close it.

*Nestor: refusal-styled human-decision act. The machine proposes
the words; a curator's judgment says whether the words are the
words. Do not soften "not recorded."*

## Skirnir — Emissary. Gate-witness.

From `personas/skirnir.md`, `not_do` clause verbatim:

> **What you do not do:** Fill gaps with inference. Distort to smooth.
> Pretend you did not witness something inconvenient.

**Distance from Willow's clause:**

| Willow refuses | Skirnir refuses |
|---|---|
| Commit without ratification | (not named) |
| PR without ratification | (not named) |
| Merge without ratification | (not named) |
| Patch without ratification | (not named) |
| Wire the fleet without ratification | (not named) |
| Read discussion as authorization | (not named — but *"pretend you did not witness"* covers a related attestation failure) |
| Write outside the active tree | (not named) |
| Cushion "not recorded" | *"distort to smooth"* — thematically related |

Skirnir's `permissions` in `specialists.json`: `dispatch_read`,
`context`, `grove_read`. She is read-only across dispatch and Grove;
she carries no `grove_write`. Her `deny_tools` is empty `[]` — a real
gap, since she has no `store_put` or `task_submit` denied even though
her mandate is witness-only.

**Machine-surfaced observation:** Skirnir's persona voice is
attestation-shaped: distortion refusals, inference refusals. Her
`permissions` are read-only, which correctly bounds her trust
elevation. But her `deny_tools: []` is unusually thin for a persona
whose mandate does not include implementation — Vishwakarma
(non-implementer) denies `task_submit`; Skirnir denies nothing at all.

**Two proposals (not applied):**

1. **Voice-level:** Extend Skirnir's `not_do` to explicitly refuse
   attesting to something she did not witness first-hand:

   > **What you do not do:** Fill gaps with inference. Distort to
   > smooth. Pretend you did not witness something inconvenient.
   > Attest to a gate crossing you did not personally observe — a
   > witness who was not present has no witness to give.

2. **Permission-level:** Add `store_put`, `store_update`,
   `store_delete`, `task_submit`, `kb_promote`, `kb_journal`,
   `knowledge_ingest` to Skirnir's `deny_tools`. She is a
   witness-only role; nothing in her mandate calls for write access
   to any of these.

*Nestor: The machine proposes. The human decides which of the two
kinds of change (voice-level or permission-level) is right, or both,
or neither. The proposal is not an amendment.*

---

## What is NOT in this review

- **Steve, Ganesha, Kart, and the other OPERATOR-tier personas from
  the runtime `fleet_personas.json`** are not in `willow-mcp`'s
  canonical roster. They are either grove-local (defined in Grove's
  own registry files) or exist only in the runtime snapshot's
  aggregation of multiple sources. A separate review is needed for
  each source-of-truth.
- **Loki (also OPERATOR-tier)** is present in `specialists.json` but
  as an auditor, not an operator seat. His `not_do` explicitly
  forbids build; that's the correct shape for an auditor and does
  not need §12-style ratification-gate additions.
- **Willow herself** is the reference; no changes proposed to her
  `not_do`.

---

## Decision required

Per §12 discipline, the machine does not amend persona `not_do`
clauses on its own recognition. Each proposal above needs the human
trust root's explicit approval — either to apply verbatim, apply with
edits, or refuse.

When ratifications land, they seal as:

- A commit to `personas/ada.md` and/or `personas/skirnir.md` with the
  new `not_do` text, `Persona: heimdallr` trailer (Heimdallr files the
  record; the human authored the ratification).
- A commit to `src/willow_mcp/bundle/config/specialists.json`
  extending `skirnir.deny_tools` if permission-level is chosen.

ΔΣ=42
